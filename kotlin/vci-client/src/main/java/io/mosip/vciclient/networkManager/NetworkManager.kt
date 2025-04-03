package io.mosip.vciclient.networkManager

import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.NetworkRequestTimeoutException
import okhttp3.FormBody
import okhttp3.Headers
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.InterruptedIOException
import java.util.concurrent.TimeUnit

object NetworkManager {

    private fun getClient(timeoutMillis: Long): OkHttpClient {
        return OkHttpClient.Builder()
            .callTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
            .build()
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
        timeoutMillis: Long = 10000,
    ): NetworkResponse {
        try {
            val requestBuilder = Request.Builder().url(url)

            headers?.forEach { (key, value) ->
                requestBuilder.addHeader(key, value)
            }

            when (method) {
                HttpMethod.GET -> requestBuilder.get()
                HttpMethod.POST -> {
                    val formBodyBuilder = FormBody.Builder()
                    bodyParams?.forEach { (key, value) -> formBodyBuilder.add(key, value) }
                    requestBuilder.post(formBodyBuilder.build())
                }
            }

            val client = getClient(timeoutMillis)
            val response = client.newCall(requestBuilder.build()).execute()

            if (!response.isSuccessful) {
                throw NetworkRequestFailedException(
                    "HTTP ${response.code}: ${response.message}"
                )
            }

            val responseBody =
                response.body?.byteStream()?.bufferedReader().use { it?.readText() } ?: ""

            return NetworkResponse(
                body = responseBody,
                headers = response.headers
            )

        } catch (e: InterruptedIOException) {
            throw NetworkRequestTimeoutException()
        } catch (e: Exception) {
            throw NetworkRequestFailedException(e.message ?: "Unknown error")
        }
    }
}

data class NetworkResponse(
    val body: String,
    val headers: Headers,
)
