package io.mosip.vciclient.token

import io.mosip.vciclient.constants.GrantType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class TokenService {
    suspend fun getAccessToken(
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        tokenEndpoint: String,
        preAuthCode: String,
        txCode: String? = null,
    ): TokenResponse = obtainAccessToken(
        grantType = GrantType.PRE_AUTHORIZED,
        getTokenResponse = getTokenResponse,
        tokenEndpoint = tokenEndpoint,
        preAuthCode = preAuthCode,
        txCode = txCode
    )

    suspend fun getAccessToken(
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        tokenEndpoint: String,
        authCode: String,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
    ): TokenResponse = obtainAccessToken(
        grantType = GrantType.AUTHORIZATION_CODE,
        getTokenResponse = getTokenResponse,
        tokenEndpoint = tokenEndpoint,
        authCode = authCode,
        clientId = clientId,
        redirectUri = redirectUri,
        codeVerifier = codeVerifier
    )

    private suspend fun obtainAccessToken(
        grantType: GrantType,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        tokenEndpoint: String,
        preAuthCode: String? = null,
        txCode: String? = null,
        authCode: String? = null,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
    ): TokenResponse {
        val tokenRequest = TokenRequest(
            grantType,
            tokenEndpoint,
            authCode,
            preAuthCode,
            txCode,
            clientId,
            redirectUri,
            codeVerifier
        )
        return withContext(Dispatchers.IO) {
            getTokenResponse(
                tokenRequest
            )
        }
    }
}
