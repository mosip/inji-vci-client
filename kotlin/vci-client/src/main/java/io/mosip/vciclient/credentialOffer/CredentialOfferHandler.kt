package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.OfferFetchFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthFlow.PreAuthFlowService
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse

class CredentialOfferHandler {

    suspend fun downloadCredentials(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: (suspend (inputMode: String?, description: String?, length: Int?) -> String)?,
        authorizeUser: suspend (authorizationEndpoint: String) -> String,
        getTokenResponse: suspend (tokenRequest: TokenRequest) -> TokenResponse,
        getProofJwt: suspend (
            credentialIssuer: String,
            cNonce: String?,
            proofSigningAlgosSupported: List<String>
        ) -> String,
        onCheckIssuerTrust: (suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean)? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        val offer =  CredentialOfferService().fetchCredentialOffer(credentialOffer)
        val credentialConfigId = offer.credentialConfigurationIds.firstOrNull() ?: ""
        val issuerMetadataResponse = IssuerMetadataService().fetchIssuerMetadataResult(
            issuerUri = offer.credentialIssuer,
            credentialConfigurationId = credentialConfigId
        )

        val issuerDisplay = issuerMetadataResponse.raw["display"] as? List<Map<String, Any>> ?: listOf(emptyMap())
        ensureIssuerTrust(
            credentialIssuer = offer.credentialIssuer,
            issuerDisplay = issuerDisplay,
            onCheckIssuerTrust = onCheckIssuerTrust
        )

        return when {
            offer.isPreAuthorizedFlow() -> {
                PreAuthFlowService().requestCredentials(
                    issuerMetadataResult = issuerMetadataResponse,
                    offer = offer,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    credentialConfigurationId = credentialConfigId,
                    getTxCode = getTxCode,
                    downloadTimeoutInMillis = downloadTimeoutInMillis
                )
            }
            offer.isAuthorizationCodeFlow() -> {
                AuthorizationCodeFlowService().requestCredentials(
                    issuerMetadataResult = issuerMetadataResponse,
                    clientMetadata = clientMetadata,
                    getTokenResponse = getTokenResponse,
                    authorizeUser = authorizeUser,
                    getProofJwt = getProofJwt,
                    credentialConfigurationId = offer.credentialConfigurationIds.first(),
                    credentialOffer = offer,
                    downloadTimeOutInMillis = downloadTimeoutInMillis
                )
            }
            else -> {
                throw OfferFetchFailedException("Credential offer does not contain a supported grant type")
            }
        }
    }

    private suspend fun ensureIssuerTrust(
        credentialIssuer: String,
        issuerDisplay: List<Map<String, Any>>,
        onCheckIssuerTrust: (suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean)?
    ) {
        if (onCheckIssuerTrust != null) {
            val consented = onCheckIssuerTrust(credentialIssuer, issuerDisplay)
            if (!consented) {
                throw OfferFetchFailedException("Issuer not trusted by user")
            }
        }
    }
}



