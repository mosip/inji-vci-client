package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.constants.CodeChallengeMethod
import io.mosip.vciclient.constants.ResponseType
import java.net.URLEncoder

object AuthorizationUrlBuilder {
    fun build(
        baseUrl: String,
        clientId: String,
        redirectUri: String,
        scope: String,
        responseType: ResponseType = ResponseType.CODE,
        state: String,
        codeChallenge: String,
        codeChallengeMethod: CodeChallengeMethod = CodeChallengeMethod.S256,
        nonce: String
    ): String {
        return buildString {
            append(baseUrl)
            append("?client_id=").append(encode(clientId))
            append("&redirect_uri=").append(encode(redirectUri))
            append("&response_type=").append(encode(responseType.value))
            append("&scope=").append(encode(scope))
            append("&state=").append(encode(state))
            append("&code_challenge=").append(encode(codeChallenge))
            append("&code_challenge_method=").append(encode(codeChallengeMethod.value))
            append("&nonce=").append(encode(nonce))
        }
    }

    private fun encode(value: String): String =
        URLEncoder.encode(value, "UTF-8")
}
