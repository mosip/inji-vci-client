package io.mosip.vciclient.credentialOffer

fun CredentialOffer.isPreAuthorizedFlow(): Boolean {
    return grants?.preAuthorizedGrant != null
}

fun CredentialOffer.isAuthorizationCodeFlow(): Boolean {
    return grants?.authorizationCodeGrant != null || grants == null
}
