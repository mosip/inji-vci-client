package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.AuthorizationResponseType
import io.mosip.vciclient.constants.CodeChallengeMethod
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.constants.Constants.APPLICATION_X_WWW_FORM_URLENCODED
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.exception.PushedAuthorizationRequestException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.logging.Logger

class PushedAuthorizationRequestService {
    private val logger = Logger.getLogger(javaClass.simpleName)

    suspend fun pushAuthorizationRequest(
        parEndpoint: String,
        clientId: String,
        redirectUri: String,
        codeChallenge: String,
        state: String,
        nonce: String,
        scope: String? = null,
        authorizationDetails: String? = null,
        issuerState: String? = null,
        codeChallengeMethod: CodeChallengeMethod = CodeChallengeMethod.S256,
        responseType: AuthorizationResponseType = AuthorizationResponseType.CODE,
        clientAuthParams: Map<String, String> = emptyMap(),
        timeoutMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): PushedAuthorizationResponse = withContext(Dispatchers.IO) {
        val params = mutableMapOf<String, String>()
        // Client authentication params are applied first so the core authorization
        // request params below always take precedence and cannot be overwritten.
        params.putAll(clientAuthParams)
        params["response_type"] = responseType.value
        params["client_id"] = clientId
        params["redirect_uri"] = redirectUri
        params["code_challenge"] = codeChallenge
        params["code_challenge_method"] = codeChallengeMethod.value
        params["state"] = state
        params["nonce"] = nonce
        if (!authorizationDetails.isNullOrBlank()) {
            params["authorization_details"] = authorizationDetails
        } else if (!scope.isNullOrBlank()) {
            params["scope"] = scope
        } else {
            throw PushedAuthorizationRequestException(
                "Either scope or authorization_details must be provided for a PAR request"
            )
        }
        if (!issuerState.isNullOrBlank()) params["issuer_state"] = issuerState

        logger.info("Pushing authorization request to PAR endpoint: $parEndpoint")

        val response = try {
            NetworkManager.sendRequest(
                url = parEndpoint,
                method = HttpMethod.POST,
                headers = mapOf(CONTENT_TYPE to APPLICATION_X_WWW_FORM_URLENCODED),
                bodyParams = params,
                timeoutMillis = timeoutMillis,
            )
        } catch (e: VCIClientException) {
            throw PushedAuthorizationRequestException(
                "PAR request failed at $parEndpoint: ${e.message}",
                issuerErrorCode = e.issuerErrorCode,
                issuerErrorDescription = e.issuerErrorDescription,
                cause = e,
            )
        } catch (e: Exception) {
            throw PushedAuthorizationRequestException(
                "PAR request failed at $parEndpoint: ${e.message}",
                issuerErrorCode = null,
                issuerErrorDescription = null,
                cause = e,
            )
        }

        val parResponse = JsonUtils.deserialize(
            response.body, PushedAuthorizationResponse::class.java
        )
        if (parResponse == null || parResponse.requestUri.isNullOrBlank()) {
            throw PushedAuthorizationRequestException(
                "Invalid PAR response from $parEndpoint: missing request_uri"
            )
        }
        parResponse
    }
}
