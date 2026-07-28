package io.mosip.vciclient.constants

object Constants {
    const val DEFAULT_NETWORK_TIMEOUT_IN_MILLIS: Long = 10000
    const val ACCEPT = "Accept"
    const val CONTENT_TYPE = "Content-Type"

    const val APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"
    const val APPLICATION_JSON = "application/json"

    const val MISSING_INTERACTION_TYPE_ERROR = "missing_interaction_type"

    const val AUTHORIZATION_HEADER = "Authorization"
    const val DPOP_HEADER = "DPoP"
    const val DPOP_NONCE_HEADER = "DPoP-Nonce"
    const val WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"

    const val DPOP_JWT_TYPE = "dpop+jwt"
    const val DPOP_TOKEN_TYPE = "DPoP"
    const val BEARER_TOKEN_TYPE = "Bearer"

    const val USE_DPOP_NONCE_ERROR = "use_dpop_nonce"

    const val HTTP_METHOD_POST = "POST"
    const val DPOP_PROOF_LIFETIME_SECONDS = 60L
}
