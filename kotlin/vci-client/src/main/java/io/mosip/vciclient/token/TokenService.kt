package io.mosip.vciclient.token

import io.mosip.vciclient.constants.GrantType
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.dpop.DPoPManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class TokenService {
    suspend fun getAccessToken(
        getTokenResponse: TokenResponseCallback,
        tokenEndpoint: String,
        preAuthCode: String,
        txCode: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): TokenResponse = obtainAccessToken(
        grantType = GrantType.PRE_AUTHORIZED,
        getTokenResponse = getTokenResponse,
        tokenEndpoint = tokenEndpoint,
        preAuthCode = preAuthCode,
        txCode = txCode,
        dpopManager = dpopManager
    )

    suspend fun getAccessToken(
        getTokenResponse: TokenResponseCallback,
        tokenEndpoint: String,
        authCode: String,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): TokenResponse = obtainAccessToken(
        grantType = GrantType.AUTHORIZATION_CODE,
        getTokenResponse = getTokenResponse,
        tokenEndpoint = tokenEndpoint,
        authCode = authCode,
        clientId = clientId,
        redirectUri = redirectUri,
        codeVerifier = codeVerifier,
        dpopManager = dpopManager
    )

    private suspend fun obtainAccessToken(
        grantType: GrantType,
        getTokenResponse: TokenResponseCallback,
        tokenEndpoint: String,
        preAuthCode: String? = null,
        txCode: String? = null,
        authCode: String? = null,
        clientId: String? = null,
        redirectUri: String? = null,
        codeVerifier: String? = null,
        dpopManager: DPoPManager = DPoPManager(),
    ): TokenResponse {
        val dpopProof = if (dpopManager.isInitialized) dpopManager.generateTokenProof() else null
        val tokenRequest = TokenRequest(
            grantType,
            tokenEndpoint,
            authCode,
            preAuthCode,
            txCode,
            clientId,
            redirectUri,
            codeVerifier,
            dpopProof
        )
        return withContext(Dispatchers.IO) {
            getTokenResponse(
                tokenRequest
            )
        }
    }
}
