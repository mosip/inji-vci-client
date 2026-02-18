package io.mosip.vciclient.credential.request

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidPublicKeyException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.proof.Proof
import java.util.logging.Logger

class CredentialRequestExecutor {

    private val logTag = Util.getLogTag(javaClass.simpleName, "")
    private val logger = Logger.getLogger(logTag)

    @Throws(
        DownloadFailedException::class,
    )
    fun requestCredential(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        proof: Proof,
        accessToken: String,
        downloadTimeoutInMillis: Long? = 10000,
    ): CredentialResponse? {

        val timeout = downloadTimeoutInMillis ?: 10000

        try {

            val request = CredentialRequestFactory.createCredentialRequest(
                issuerMetadata.credentialFormat,
                accessToken,
                issuerMetadata,
                proof
            )

            val networkResponse = NetworkManager.sendRequest(
                request = request,
                timeoutMillis = timeout
            )

            val responseBody = networkResponse.body

            logger.info("Credential downloaded successfully")

            if (responseBody.isNotBlank()) {

                val credentialResponse =
                    JsonUtils.deserialize(responseBody, CredentialResponse::class.java)

                credentialResponse?.credentialConfigurationId = credentialConfigurationId
                credentialResponse?.credentialIssuer = issuerMetadata.credentialIssuer

                return credentialResponse
            }

            logger.warning("Credential endpoint returned empty body")
            return null

        } catch (e: NetworkRequestTimeoutException) {
            logger.severe("Credential download timed out after ${timeout / 1000}s")
            throw DownloadFailedException(
                message = "Credential download timed out after ${timeout / 1000}s",
                cause = e,
            )
        } catch (e: NetworkRequestFailedException) {
            logger.severe("Credential download failed: ${e.message}")
            throw DownloadFailedException(
                message = e.message,
                cause = e,
                serverErrorCode = e.serverErrorCode,
                serverErrorDescription = e.serverErrorDescription
            )
        } catch (e: InvalidPublicKeyException) {
            throw DownloadFailedException(
                e.message,
                cause = e
            )
        } catch (e: Exception) {
            logger.severe("Unexpected error during credential download: ${e.message}")
            throw DownloadFailedException(
                message = e.message,
                cause = e
            )
        }
    }
}
