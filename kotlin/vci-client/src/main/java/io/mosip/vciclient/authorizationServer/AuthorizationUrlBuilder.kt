package io.mosip.vciclient.authorizationServer


import java.net.URLEncoder

object AuthorizationUrlBuilder {
    fun build(
        baseUrl: String,
        clientId: String,
        redirectUri: String,
        scope: String,
        responseType: String = "code",
        state: String,
        codeChallenge: String,
        codeChallengeMethod: String = "S256",
        nonce: String
    ): String {
        return buildString {
            append(baseUrl)
            append("?client_id=").append(encode(clientId))
            append("&redirect_uri=").append(encode(redirectUri))
            append("&response_type=").append(encode(responseType))
            append("&scope=").append(encode(scope))
            append("&state=").append(encode(state))
            append("&code_challenge=").append(encode(codeChallenge))
            append("&code_challenge_method=").append(encode(codeChallengeMethod))
            append("&nonce=").append(encode(nonce))
        }
    }

    private fun encode(value: String): String =
        URLEncoder.encode(value, "UTF-8")
}
