package io.mosip.vciclient.credentialRequestFlowHandlers

import io.mosip.vciclient.authorizationFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialOffer.CredentialOfferService
import io.mosip.vciclient.credentialOffer.isAuthorizationCodeFlow
import io.mosip.vciclient.credentialOffer.isPreAuthorizedFlow
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.OfferFetchFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthFlow.PreAuthFlowService

class CredentialOfferHandler {
    suspend fun downloadCredentials(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        txCode: (suspend (inputMode: String?, description: String?, length: Int?) -> String)?,
        proofJwt: suspend (accessToken: String, cNonce: String?, issuerMetadata: Map<String, *>?, credentialConfigurationId: String?) -> String,
        authCode: suspend (authorisationEndpoint: String) -> String,
        onCheckIssuerTrust: (suspend (Map<String, Any>) -> Boolean)?,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
        traceabilityId: String? = null,
    ): CredentialResponse {
        val offer: CredentialOffer = CredentialOfferService().fetchCredentialOffer(credentialOffer)
        val issuerMetaData = IssuerMetadataService().fetch(
            offer.credentialIssuer, offer.credentialConfigurationIds[0]
        )
        ensureIssuerTrust(
            rawMetadata = issuerMetaData.raw,
            onCheckIssuerTrust = onCheckIssuerTrust,
        )
        return when {
            offer.isPreAuthorizedFlow() -> {
                PreAuthFlowService().requestCredentials(
                    issuerMetaData,
                    offer,
                    txCode,
                    proofJwt,
                    offer.credentialConfigurationIds[0],
                    downloadTimeoutInMillis,
                    traceabilityId
                )
            }

            offer.isAuthorizationCodeFlow() -> {
                AuthorizationCodeFlowService().requestCredentials(
                    issuerMetaData,
                    clientMetadata,
                    offer,
                    authCode,
                    proofJwt,
                    offer.credentialConfigurationIds[0],
                    downloadTimeoutInMillis,
                    traceabilityId
                )
            }

            else -> {
                throw OfferFetchFailedException("Credential offer does not contain a supported grant type")
            }
        } ?: throw OfferFetchFailedException("No credential response found")
    }

    private suspend fun ensureIssuerTrust(
        rawMetadata: Map<String, Any>,
        onCheckIssuerTrust: (suspend (Map<String, Any>) -> Boolean)?,
    ) {

        if (onCheckIssuerTrust != null) {
            val consented = onCheckIssuerTrust(rawMetadata)
            if (!consented) {
                throw OfferFetchFailedException("Issuer not trusted by user")
            }
        }
    }

}



