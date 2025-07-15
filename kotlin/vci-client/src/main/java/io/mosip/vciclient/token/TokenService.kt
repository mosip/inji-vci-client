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
    ): TokenResponse = fetchAccessToken(
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
    ): TokenResponse = fetchAccessToken(
        grantType = GrantType.AUTHORIZATION_CODE,
        getTokenResponse = getTokenResponse,
        tokenEndpoint = tokenEndpoint,
        authCode = authCode,
        clientId = clientId,
        redirectUri = redirectUri,
        codeVerifier = codeVerifier
    )

    //TODO: timeoutMillis is not used in the function
    private suspend fun fetchAccessToken(
        grantType: GrantType,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        tokenEndpoint: String,
        preAuthCode: String? = null,
        txCode: String? = null,
        authCode: String? = null,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
    ): TokenResponse = withContext(Dispatchers.IO) {
        val tokenRequest = TokenRequest(
            grantType = grantType,
            tokenEndpoint = tokenEndpoint,
            authCode = authCode,
            preAuthorizedCode = preAuthCode,
            txCode = txCode,
            clientId = clientId,
            redirectUri = redirectUri,
            codeVerifier = codeVerifier
        )
        getTokenResponse(tokenRequest)
    }
}
