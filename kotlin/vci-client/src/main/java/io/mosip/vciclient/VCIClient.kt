package io.mosip.vciclient

import PreAuthTokenService
import android.util.Log
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.common.Util
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialOffer.CredentialOfferService
import io.mosip.vciclient.credentialRequest.CredentialRequestFactory
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.exception.InvalidPublicKeyException
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import io.mosip.vciclient.exception.OfferFetchFailedException
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.proof.jwt.JWTProof
import okhttp3.OkHttpClient
import okhttp3.Response
import java.io.IOException
import java.io.InterruptedIOException
import java.net.URI
import java.net.URLDecoder
import java.util.concurrent.TimeUnit

class VCIClient(traceabilityId: String) {
    private val logTag = Util.getLogTag(javaClass.simpleName, traceabilityId)

    @Throws(
        DownloadFailedException::class,
        InvalidAccessTokenException::class,
        NetworkRequestTimeoutException::class,
        InvalidPublicKeyException::class
    )
    fun requestCredential(
        issuerMetaData: IssuerMetaData,
        proof: Proof,
        accessToken: String,
    ): CredentialResponse? {

        try {
            val client = OkHttpClient.Builder()
                .callTimeout(
                    issuerMetaData.downloadTimeoutInMilliSeconds.toLong(),
                    TimeUnit.MILLISECONDS
                )
                .build()

            val request = CredentialRequestFactory.createCredentialRequest(
                issuerMetaData.credentialFormat,
                accessToken,
                issuerMetaData,
                proof
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
                "Network request for ${issuerMetaData.credentialEndpoint} took more than expected time(${issuerMetaData.downloadTimeoutInMilliSeconds / 1000}s). Exception - $exception"
            )
            throw NetworkRequestTimeoutException()
        } catch (exception: IOException) {
            Log.e(
                logTag,
                "Network request failed due to Exception - $exception"
            )
            throw NetworkRequestFailedException("${exception.message} ${exception.cause}")
        } catch (exception: Exception) {
            if (exception is DownloadFailedException || exception is InvalidAccessTokenException || exception is InvalidPublicKeyException)
                throw exception
            Log.e(
                logTag,
                "Downloading credential failed due to ${exception.message}"
            )
            throw DownloadFailedException(exception.message!!)
        }
    }

    @Throws(
        DownloadFailedException::class,
        InvalidAccessTokenException::class,
        NetworkRequestTimeoutException::class,
        InvalidPublicKeyException::class
    )
    suspend fun requestCredentialByPreAuthFlow(
        issuerMetaData: IssuerMetaData,
        txCode: String?,
        getProofJwt: suspend (accessToken: String, cNonce: String?) -> String,
    ): CredentialResponse? {
        val token = PreAuthTokenService().exchangePreAuthCodeForToken(issuerMetaData, txCode)
        val jwt = getProofJwt(token.accessToken,token.cNonce)
        val proof= JWTProof(jwt)
    return requestCredential(issuerMetaData, proof, token.accessToken)
    }

    fun fetchCredentialOfferIssuer(credentialOfferData: String): CredentialOffer {
        try {
            val normalized = credentialOfferData.replace(
                "openid-credential-offer://?",
                "openid-credential-offer://dummy?"
            )
            val uri = URI(normalized)
            val queryParams = uri.rawQuery
                ?.split("&")
                ?.associate {
                    val (key, value) = it.split("=")
                    key to URLDecoder.decode(value, "UTF-8")
                } ?: throw OfferFetchFailedException("No query parameters in the URI")

            val credentialOfferService = CredentialOfferService()

            return when {
                queryParams.containsKey("credential_offer") -> {
                    val offer = queryParams["credential_offer"]!!
                    credentialOfferService.handleByValueOffer(offer)
                }

                queryParams.containsKey("credential_offer_uri") -> {
                    val uriOffer = queryParams["credential_offer_uri"]!!
                    credentialOfferService.handleByReferenceOffer(uriOffer)
                }

                else -> throw OfferFetchFailedException(
                    "Invalid credential offer URL: must contain 'credential_offer' or 'credential_offer_uri'"
                )

            }

        } catch (e: Exception) {
            throw OfferFetchFailedException("Failed to fetch credential offer: ${e.message}")
        }
    }
}
