package io.mosip.vciclient.networkManager

import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import okhttp3.FormBody
import okhttp3.Headers
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

private const val ERROR_CODE = "error"
private const val ERROR_DESCRIPTION = "error_description"

object NetworkManager {

    private val baseClient = OkHttpClient()

    private fun getClient(timeoutMillis: Long): OkHttpClient =
        baseClient.newBuilder()
            .callTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            .build()

    @Throws(
        NetworkRequestTimeoutException::class,
        NetworkRequestFailedException::class
    )
    fun sendRequest(
        request: Request,
        timeoutMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): NetworkResponse {

        try {
            val client = getClient(timeoutMillis)

            client.newCall(request).execute().use { response ->

                val responseBody = response.body?.string().orEmpty()

                if (!response.isSuccessful) {
                    val (serverErrorCode, serverErrorDescription) =
                        parseServerErrorResponse(responseBody)

                    throw NetworkRequestFailedException(
                        message = "HTTP ${response.code}",
                        serverErrorCode = serverErrorCode,
                        serverErrorDescription = serverErrorDescription
                    )
                }

                return NetworkResponse(
                    body = responseBody,
                    headers = response.headers
                )
            }

        } catch (e: InterruptedIOException) {
            throw NetworkRequestTimeoutException(
                message = e.message,
                cause = e
            )
        } catch (e: NetworkRequestFailedException) {
            throw e
        } catch (e: Exception) {
            throw NetworkRequestFailedException(
                message = e.message ?: "Unknown error",
                cause = e
            )
        }
    }


    @Throws(
        NetworkRequestTimeoutException::class,
        NetworkRequestFailedException::class
    )
    fun sendRequest(
        url: String,
        method: HttpMethod,
        headers: Map<String, String>? = null,
        bodyParams: Map<String, String>? = null,
        timeoutMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): NetworkResponse {

        val requestBuilder = Request.Builder().url(url)

        headers?.forEach { (key, value) ->
            requestBuilder.addHeader(key, value)
        }

        when (method) {
            HttpMethod.GET -> requestBuilder.get()
            HttpMethod.POST -> {
                val formBodyBuilder = FormBody.Builder()
                bodyParams?.forEach { (key, value) ->
                    formBodyBuilder.add(key, value)
                }
                requestBuilder.post(formBodyBuilder.build())
            }
        }

        return sendRequest(
            request = requestBuilder.build(),
            timeoutMillis = timeoutMillis
        )
    }


    private fun parseServerErrorResponse(responseBody: String): Pair<String?, String?> {
        var serverErrorCode: String? = null
        var serverErrorDescription: String? = null

        try {
            val json = JSONObject(responseBody)
            serverErrorCode = json.optString(ERROR_CODE)
            serverErrorDescription = json.optString(ERROR_DESCRIPTION)
        } catch (_: Exception) {
            Logger.getLogger(NetworkManager::class.java.name)
                .warning("Failed to parse server error response")
            return Pair(null, responseBody)
        }
        return Pair(serverErrorCode, serverErrorDescription)
    }
}

data class NetworkResponse(
    val body: String,
    val headers: Headers?,
)
