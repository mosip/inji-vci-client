package io.mosip.vciclient.token

import io.mosip.vciclient.constants.GrantType

data class TokenRequest(
    val grantType: GrantType,
    val tokenEndpoint: String,
    val authCode: String?,
    val preAuthCode: String?,
    val txCode: String?,
    val clientId: String?,
    val redirectUri: String?,
    val codeVerifier: String?
)
