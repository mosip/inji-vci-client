package io.mosip.vciclient.credentialRequest;

import android.util.Log
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.DownloadFailedException;
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

class CredentialRequestExecutor (val traceabilityId: String? = null){

    private val logTag = Util.getLogTag(javaClass.simpleName,traceabilityId)
    @Throws(
            DownloadFailedException::class,
            InvalidAccessTokenException::class,
            NetworkRequestTimeoutException::class,
            InvalidPublicKeyException::class
    )
    fun requestCredential(
        issuerMetadata: IssuerMetadata,
        proof: Proof,
        accessToken: String,
        downloadTimeoutInMilliSeconds: Long? = 10000,
            ): CredentialResponse? {

        try {
            val client = OkHttpClient.Builder().callTimeout(
                    downloadTimeoutInMilliSeconds!!, TimeUnit.MILLISECONDS
                ).build()

            val request = CredentialRequestFactory.createCredentialRequest(
                    issuerMetadata.credentialFormat, accessToken, issuerMetadata, proof,
            )
            val response: Response = client.newCall(request).execute()

            if (response.code != 200) {
                val errorResponse: String? = response.body?.string()
                Log.e(
                        logTag,
                        "Downloading credential failed with response code ${response.code} - ${response.message}. Error - $errorResponse"
                )
                if (errorResponse != "" && errorResponse != null) {
                    throw DownloadFailedException(errorResponse)
                }
                throw DownloadFailedException(response.message)
            }
            val responseBody: String =
                    response.body?.byteStream()?.bufferedReader().use { it?.readText() } ?: ""
            Log.d(logTag, "credential downloaded successfully!")

            if (responseBody != "") {
                return JsonUtils.deserialize(responseBody, CredentialResponse::class.java)

            }

            Log.w(
                    logTag,
                    "The response body from credentialEndpoint is empty, responseCode - ${response.code}, responseMessage ${response.message}, returning null."
            )
            return null
        } catch (exception: InterruptedIOException) {
            Log.e(
                    logTag,
                    "Network request for ${issuerMetadata.credentialEndpoint} took more than expected time(${downloadTimeoutInMilliSeconds!! / 1000}s). Exception - $exception"
            )
            throw NetworkRequestTimeoutException("")
        } catch (exception: IOException) {
            Log.e(
                    logTag, "Network request failed due to Exception - $exception"
            )
            throw NetworkRequestFailedException(exception.message)
        } catch (exception: Exception) {
            if (exception is DownloadFailedException || exception is InvalidAccessTokenException || exception is InvalidPublicKeyException) throw exception
            Log.e(
                    logTag, "Downloading credential failed due to ${exception.message}"
            )
            throw DownloadFailedException(exception.message!!)
        }
    }
}
