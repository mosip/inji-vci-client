package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.exception.OfferFetchFailedException

object CredentialOfferValidator {

    fun validate(offer: CredentialOffer) {
        validateCredentialIssuer(offer.credentialIssuer)
        validateCredentialConfigurationIds(offer.credentialConfigurationIds)
        validateGrants(offer.grants)
    }

    private fun validateCredentialIssuer(issuer: String) {
        if (issuer.isBlank()) {
            throw OfferFetchFailedException("credential_issuer must not be blank")
        }
        if (!issuer.startsWith("https://")) {
            throw OfferFetchFailedException("credential_issuer must use HTTPS scheme")
        }
    }

    private fun validateCredentialConfigurationIds(configIds: List<String>) {
        if (configIds.isEmpty()) {
            throw OfferFetchFailedException("credential_configuration_ids must not be empty")
        }
        if (configIds.any { it.isBlank() }) {
            throw OfferFetchFailedException("credential_configuration_ids must not contain blank values")
        }
    }

    private fun validateGrants(grants: CredentialOfferGrants?) {
        if (grants == null) return

        if (grants.authorizationCodeGrant == null && grants.preAuthorizedGrant == null) {
            throw OfferFetchFailedException("grants must contain at least one supported grant type")
        }

        grants.preAuthorizedGrant?.let {
            if (it.preAuthorizedCode.isBlank()) {
                throw OfferFetchFailedException("pre-authorized_code must not be blank")
            }
            it.txCode?.let { tx ->
                if (tx.length != null && tx.length <= 0) {
                    throw OfferFetchFailedException("tx_code.length must be greater than 0")
                }
            }
        }
    }

}
