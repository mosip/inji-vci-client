package io.mosip.vciclient.credential.request

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.exception.InvalidPublicKeyException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import okhttp3.OkHttpClient
import okhttp3.Response
import okio.IOException
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

class CredentialRequestExecutor {

    private val logTag = Util.getLogTag(javaClass.simpleName)
    private val logger = Logger.getLogger(logTag)

    @Throws(
        DownloadFailedException::class,
        InvalidAccessTokenException::class,
        NetworkRequestTimeoutException::class,
        InvalidPublicKeyException::class
    )
    fun requestCredential(
        issuerMetadata: IssuerMetadata,
        credentialConfigurationId: String,
        proof: Proof,
        accessToken: String,
        downloadTimeoutInMillis: Long? = 10000,
    ): CredentialResponse? {

        try {
            val client = OkHttpClient.Builder().callTimeout(
                downloadTimeoutInMillis!!, TimeUnit.MILLISECONDS
            ).build()

            val request = CredentialRequestFactory.createCredentialRequest(
                issuerMetadata.credentialFormat, accessToken, issuerMetadata, proof,
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
                val credentialResponse =
                    JsonUtils.deserialize(responseBody, CredentialResponse::class.java)
                credentialResponse?.credentialConfigurationId = credentialConfigurationId
                credentialResponse?.credentialIssuer = issuerMetadata.credentialIssuer
                return credentialResponse
            }

            logger.warning(
                "The response body from credentialEndpoint is empty, responseCode - ${response.code}, responseMessage ${response.message}, returning null."
            )
            return null
        } catch (exception: InterruptedIOException) {
            logger.severe(
                "Network request for ${issuerMetadata.credentialEndpoint} took more than expected time(${downloadTimeoutInMillis!! / 1000}s). Exception - $exception"
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
