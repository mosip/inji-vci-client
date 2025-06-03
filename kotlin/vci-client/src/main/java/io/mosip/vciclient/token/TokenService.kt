package io.mosip.vciclient.token

import android.util.Log
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.exception.InvalidAccessTokenException
import io.mosip.vciclient.grant.GrantType
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class TokenService {

    suspend fun getAccessToken(
        tokenEndpoint: String,
        timeoutMillis: Long? = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        preAuthCode: String,
        txCode: String? = null,
    ): TokenResponse = fetchAccessToken(
        grantType = GrantType.PRE_AUTHORIZED,
        tokenEndpoint = tokenEndpoint,
        timeoutMillis = timeoutMillis!!,
        preAuthCode = preAuthCode,
        txCode = txCode
    )

    suspend fun getAccessToken(
        tokenEndpoint: String,
        timeoutMillis: Long? = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        authCode: String,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
    ): TokenResponse = fetchAccessToken(
        grantType = GrantType.AUTHORIZATION_CODE,
        tokenEndpoint = tokenEndpoint,
        timeoutMillis = timeoutMillis!!,
        authCode = authCode,
        clientId = clientId,
        redirectUri = redirectUri,
        codeVerifier = codeVerifier
    )

    private suspend fun fetchAccessToken(
        grantType: GrantType,
        tokenEndpoint: String,
        timeoutMillis: Long,
        preAuthCode: String? = null,
        txCode: String? = null,
        authCode: String? = null,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
    ): TokenResponse = withContext(Dispatchers.IO) {

        val headers = mapOf("Content-Type" to "application/x-www-form-urlencoded")
        val bodyParams = buildBodyParams(
            grantType, preAuthCode, txCode, authCode, clientId, redirectUri, codeVerifier
        )
        Log.d("tokenRequest", "$bodyParams $tokenEndpoint")

        val response = NetworkManager.sendRequest(
            url = tokenEndpoint,
            method = HttpMethod.POST,
            headers = headers,
            bodyParams = bodyParams,
            timeoutMillis = timeoutMillis
        )

        parseTokenResponse(response.body)
    }

    private fun buildBodyParams(
        grantType: GrantType,
        preAuthCode: String?,
        txCode: String?,
        authCode: String?,
        clientId: String?,
        redirectUri: String?,
        codeVerifier: String?,
    ): Map<String, String> {
        return when (grantType) {
            GrantType.PRE_AUTHORIZED -> {
                if (preAuthCode.isNullOrBlank()) {
                    throw DownloadFailedException("Pre-authorized code is missing.")
                }
                buildMap {
                    put("grant_type", grantType.value)
                    put("pre-authorized_code", preAuthCode)
                    txCode?.let { put("tx_code", it) }
                }
            }

            GrantType.AUTHORIZATION_CODE -> {
                if (authCode.isNullOrBlank()) {
                    throw DownloadFailedException("Authorization code is missing.")
                }
                buildMap {
                    put("grant_type", grantType.value)
                    put("code", authCode)
                    clientId?.let { put("client_id", it) }
                    redirectUri?.let { put("redirect_uri", it) }
                    codeVerifier?.let { put("code_verifier", it) }
                }
            }

            else -> {throw DownloadFailedException("Unknown GrantType")}
        }
    }

    private fun parseTokenResponse(responseBody: String): TokenResponse {
        if (responseBody.isBlank()) {
            throw DownloadFailedException("Token response body is empty")
        }

        val tokenResponse = JsonUtils.deserialize(responseBody, TokenResponse::class.java)
            ?: throw InvalidAccessTokenException("Failed to parse token response")

        if (tokenResponse.accessToken.isNullOrBlank()) {
            throw InvalidAccessTokenException("Access token missing in token response")
        }

        return tokenResponse
    }
}
