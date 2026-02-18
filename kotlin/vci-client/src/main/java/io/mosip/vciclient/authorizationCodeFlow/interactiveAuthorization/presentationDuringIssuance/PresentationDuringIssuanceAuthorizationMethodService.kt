package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance

import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenV2
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResultV2
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.AuthorizationMethodService
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.AuthorizationResponse
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.constants.Constants.APPLICATION_X_WWW_FORM_URLENCODED
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.logging.Logger

class PresentationDuringIssuanceAuthorizationMethodService(
    private val selectCredentialsForPresentation: suspend (ovpRequest: AuthorizationRequest) -> Map<String, Map<FormatType, List<Any>>>,
    private val signVerifiablePresentation: suspend (
        payload: List<UnsignedVPTokenV2>,
    ) -> List<VPTokenSigningResultV2>,
    private val ldpVpSignatureSuite: String? = null,
    private val traceabilityId: String? = null,
    private val openId4vp: OpenID4VP = OpenID4VP(
        traceabilityId = traceabilityId ?: "",
        walletMetadata = null
    ),
) : AuthorizationMethodService {

    private val logTag = Util.getLogTag(javaClass.simpleName, traceabilityId)
    private val logger = Logger.getLogger(logTag)

    override fun type(): String = InteractionType.OpenId4VpPresentation.value

    override suspend fun authorizeUser(
        requestData: AuthorizationRequestData
    ): AuthorizationResponse {

        if (requestData !is PresentationDuringIssuanceRequestData) {
            throw InteractiveAuthorizationException(
                "Expected PresentationDuringIssuanceRequestData"
            )
        }

        var vpResponse: Map<String, Any>

        try {
            try {
                val authorizationRequest =
                    validatePresentationRequest(requestData.ovpRequest)

                vpResponse = handlePresentation(authorizationRequest)

            } catch (error: Exception) {
                logger.warning("Error during presentation handling: ${error.message}")
                vpResponse = openId4vp.constructErrorInfo(error)
            }

            return sendOVPAuthorizationResponseToIssuer(
                iar = requestData.iar,
                authSession = requestData.authSession,
                vpResponse = vpResponse
            )
        } catch (ex: InteractiveAuthorizationException) {
            throw ex
        } catch (ex: VCIClientException) {
            throw InteractiveAuthorizationException(
                "Error during presentation authorization: ${ex.message}",
                cause = ex,
                serverErrorCode = ex.serverErrorCode,
                serverErrorDescription = ex.serverErrorDescription
            )
        } catch (ex: Exception) {
            throw InteractiveAuthorizationException(
                "Unexpected error during interactive authorization: ${ex.message}",
                cause = ex
            )
        }

    }


    private fun validatePresentationRequest(request: Map<String, Any>): AuthorizationRequest {
        return openId4vp.authenticateVerifier(request, emptyList(), false)
    }

    private suspend fun handlePresentation(vpRequest: AuthorizationRequest): Map<String, Any> {
        val selectedCredentials = selectCredentialsForPresentation(vpRequest)

        if (selectedCredentials.isEmpty()) {
            throw OpenID4VPExceptions.AccessDenied(
                "No credentials selected by user",
                className = "PresentationDuringIssuanceAuthorizationMethodService",
            )
        }

        val holderId = extractHolderIdForLdpVc(selectedCredentials)

        val flattenedFormatEntries = selectedCredentials.values.flatMap { formatMap ->
            formatMap.map { it.key to it.value }
        }
        val hasLdpVc = flattenedFormatEntries.any { (formatType, _) ->
            formatType == FormatType.LDP_VC
        }
        if (hasLdpVc && ldpVpSignatureSuite == null) {
            throw InteractiveAuthorizationException("Missing signature suite for LDP VC")
        }

        val unsignedVpTokens = openId4vp.constructUnsignedVPTokenV2(
            verifiableCredentials = selectedCredentials,
            holderId = holderId,
            signatureSuite = ldpVpSignatureSuite
        )

        val signedVpTokens = signVerifiablePresentation(unsignedVpTokens)

        return openId4vp.constructVPResponseV2(
            vpTokenSigningResults = signedVpTokens
        )
    }

    private fun extractHolderIdForLdpVc(
        credentialsMap: Map<String, Map<FormatType, List<Any>>>
    ): String? {
        return credentialsMap.values.firstNotNullOfOrNull { formatMap ->
            val ldpVc = formatMap[FormatType.LDP_VC]?.firstOrNull()
            val vc = when (ldpVc) {
                is String -> JsonUtils.deserialize(ldpVc, Map::class.java)
                is Map<*, *> -> ldpVc
                else -> null
            }
            val credentialSubject = vc?.get("credentialSubject") as? Map<*, *>
            credentialSubject?.get("id") as? String
        }
            ?.trimEnd('=')
            ?.plus("#0")
    }


    private suspend fun sendOVPAuthorizationResponseToIssuer(
        iar: String,
        authSession: String,
        vpResponse: Map<String, Any>
    ): AuthorizationResponse {
        val responseBody = mapOf(
            "auth_session" to authSession,
            "openid4vp_response" to JsonUtils.serialize(vpResponse)
        )

        val networkResponse = try {
            withContext(Dispatchers.IO) {
                NetworkManager.sendRequest(
                    url = iar,
                    method = HttpMethod.POST,
                    bodyParams = responseBody,
                    headers = mapOf(CONTENT_TYPE to APPLICATION_X_WWW_FORM_URLENCODED)
                )
            }

        } catch (ex: InteractiveAuthorizationException) {
            throw ex
        } catch (ex: VCIClientException) {
            throw InteractiveAuthorizationException(
                "Error while posting VP response: ${ex.message}",
                cause = ex,
                serverErrorCode = ex.serverErrorCode,
                serverErrorDescription = ex.serverErrorDescription
            )
        } catch (ex: Exception) {
            throw InteractiveAuthorizationException(
                "Unexpected error while posting VP response: ${ex.message}",
                cause = ex
            )
        }

        return JsonUtils.deserialize(networkResponse.body, AuthorizationResponse::class.java)
            ?: throw InteractiveAuthorizationException("Issuer response deserialization failed")
    }
}


