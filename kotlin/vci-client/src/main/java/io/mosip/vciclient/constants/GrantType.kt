package io.mosip.vciclient.constants

enum class GrantType(val value: String) {
    PRE_AUTHORIZED("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
    AUTHORIZATION_CODE("authorization_code"),
    IMPLICIT("implicit")
}
