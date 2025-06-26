package io.mosip.vciclient

import io.mosip.vciclient.clientMetadata.ClientMetadata
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credentialRequest.CredentialRequestFactory
import io.mosip.vciclient.credentialRequestFlowHandlers.CredentialOfferHandler
import io.mosip.vciclient.credentialRequestFlowHandlers.TrustedIssuerHandler
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.exception.InvalidPublicKeyException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import okhttp3.OkHttpClient
import okhttp3.Response
import okio.IOException
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

class VCIClient(private val traceabilityId: String?) {

    private val logTag = Util.getLogTag(javaClass.simpleName, traceabilityId)
    private val logger = Logger.getLogger(logTag)
    suspend fun requestCredentialByCredentialOffer(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: (suspend (inputMode: String?, description: String?, length: Int?) -> String)?,
        getProofJwt: suspend (accessToken: String, cNonce: String?, issuerMetadata: Map<String, *>?, credentialConfigurationId: String?) -> String,
        getAuthCode: suspend (authorisationEndpoint: String) -> String,
        onCheckIssuerTrust: (suspend (issuerMetadata: Map<String, Any>) -> Boolean)? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        try {
            return CredentialOfferHandler().downloadCredentials(
                credentialOffer,
                clientMetadata,
                getTxCode,
                getProofJwt,
                getAuthCode,
                onCheckIssuerTrust,
                downloadTimeoutInMillis,
                traceabilityId
            )
        } catch (e: VCIClientException) {
            logger.severe(
                "Downloading credential failed due to ${e.message}"
            )
            throw e
        } catch (e: Exception) {
            logger.severe(
                "Downloading credential failed due to ${e.message}"
            )
            throw VCIClientException("VCI-010", "Unknown Exception - ${e.message}")
        }
    }

    suspend fun requestCredentialFromTrustedIssuer(
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        getProofJwt: suspend (
            accessToken: String,
            cNonce: String?,
            issuerMetadata: Map<String, *>?,
            credentialConfigurationId: String?,
        ) -> String,
        getAuthCode: suspend (authorizationEndpoint: String) -> String,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse? {
        try {
            return TrustedIssuerHandler().downloadCredentials(
                resolvedMeta = issuerMetadata,
                clientMetadata = clientMetadata,
                getProofJwt = getProofJwt,
                getAuthCode = getAuthCode,
                downloadTimeOutInMillis = downloadTimeoutInMillis,
                traceabilityId = traceabilityId
            )
        } catch (e: VCIClientException) {
            logger.severe(
                "Downloading credential failed due to ${e.message}"
            )
            throw e
        } catch (e: Exception) {
            logger.severe(
                "Downloading credential failed due to ${e.message}"
            )
            throw VCIClientException("VCI-010", "Unknown Exception - ${e.message}")
        }

    }

    @Deprecated(
        message = "This method is deprecated as per the new VCI Client library contract. " + "Use requestCredentialByCredentialOffer() or requestCredentialFromTrustedIssuer()",
        level = DeprecationLevel.WARNING
    )
    fun requestCredential(
        issuerMetadata: IssuerMetaData,
        proof: Proof,
        accessToken: String,
    ): CredentialResponse? {

        try {
            val client = OkHttpClient.Builder().callTimeout(
                issuerMetadata.downloadTimeoutInMilliSeconds.toLong(), TimeUnit.MILLISECONDS
            ).build()

            val metadata = IssuerMetadata(
                credentialAudience = issuerMetadata.credentialAudience,
                credentialEndpoint = issuerMetadata.credentialEndpoint,
                credentialType = issuerMetadata.credentialType?.toList(),
                credentialFormat = issuerMetadata.credentialFormat,
                doctype = issuerMetadata.doctype,
                claims = issuerMetadata.claims,
                context = null,
                authorizationServers = null,
                tokenEndpoint = null,
                scope = "openId"
            )

            val request = CredentialRequestFactory.createCredentialRequest(
                metadata.credentialFormat, accessToken, metadata, proof,
            )
            val response: Response = client.newCall(request).execute()

            if (response.code != 200) {
                val errorResponse: String? = response.body?.string()
                logger.severe(

                    "Downloading credential failed with response code ${response.code} - ${response.message}. Error - $errorResponse"
                )
                if (errorResponse != "" && errorResponse != null) {
                    throw DownloadFailedException(errorResponse)
                }
                throw DownloadFailedException(response.message)
            }
            val responseBody: String =
                response.body?.byteStream()?.bufferedReader().use { it?.readText() } ?: ""
            logger.info("credential downloaded successfully!")

            if (responseBody != "") {
                return JsonUtils.deserialize(responseBody, CredentialResponse::class.java)

            }

            logger.warning(
                "The response body from credentialEndpoint is empty, responseCode - ${response.code}, responseMessage ${response.message}, returning null."
            )
            return null
        } catch (exception: InterruptedIOException) {
            logger.severe(
                "Network request for ${issuerMetadata.credentialEndpoint} took more than expected time(${issuerMetadata.downloadTimeoutInMilliSeconds / 1000}s). Exception - $exception"
            )
            throw NetworkRequestTimeoutException("")
        } catch (exception: IOException) {
            logger.severe(
                "Network request failed due to Exception - $exception"
            )
            throw NetworkRequestFailedException(exception.message)
        } catch (exception: Exception) {
            if (exception is DownloadFailedException || exception is InvalidAccessTokenException || exception is InvalidPublicKeyException) throw exception
            logger.severe(
                "Downloading credential failed due to ${exception.message}"
            )
            throw DownloadFailedException(exception.message!!)
        }
    }

}
