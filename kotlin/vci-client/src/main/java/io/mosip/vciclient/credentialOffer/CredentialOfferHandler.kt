package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.CredentialOfferFetchFailedException
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowService
import io.mosip.vciclient.token.TokenRequest
import io.mosip.vciclient.token.TokenResponse

//TODO: TODO rename to CredentialOfferFlowHandler
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
            proofSigningAlgorithmsSupported: List<String>
        ) -> String,
        onCheckIssuerTrust: (suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean)? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        val offer =  CredentialOfferService().fetchCredentialOffer(credentialOffer)
        if (offer.credentialConfigurationIds.size > 1){
            throw DownloadFailedException("Batch credential request is not supported.")
        }
        val credentialConfigId = offer.credentialConfigurationIds.firstOrNull() ?: ""
        val issuerMetadataResponse = IssuerMetadataService().fetchIssuerMetadataResult(
            credentialIssuer = offer.credentialIssuer,
            credentialConfigurationId = credentialConfigId
        )

        val issuerDisplay = issuerMetadataResponse.raw["display"] as? List<Map<String, Any>> ?: listOf(emptyMap())
        ensureIssuerTrust(
            credentialIssuer = offer.credentialIssuer,
            issuerDisplay = issuerDisplay,
            onCheckIssuerTrust = onCheckIssuerTrust
        )

        val credentialResponse = when {
            //TODO: issuerMetadataResult -> IssuerMetadata, and send proofSigningAlgorithmsSupported
            offer.isPreAuthorizedFlow() -> {
                PreAuthCodeFlowService().requestCredentials(
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
                    credentialConfigurationId = offer.credentialConfigurationIds.first(),
                    clientMetadata = clientMetadata,
                    authorizeUser = authorizeUser,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    credentialOffer = offer,
                    downloadTimeOutInMillis = downloadTimeoutInMillis
                )
            }

            else -> {
                throw CredentialOfferFetchFailedException("Credential offer does not contain a supported grant type")
            }
        }
        if(credentialResponse.credential.isJsonNull){
            throw CredentialOfferFetchFailedException("No credential response found")
        }
        return credentialResponse
    }

    private suspend fun ensureIssuerTrust(
        credentialIssuer: String,
        issuerDisplay: List<Map<String, Any>>,
        onCheckIssuerTrust: (suspend (credentialIssuer: String, issuerDisplay: List<Map<String, Any>>) -> Boolean)?
    ) {
        if (onCheckIssuerTrust != null) {
            val consented = onCheckIssuerTrust(credentialIssuer, issuerDisplay)
            if (!consented) {
                throw CredentialOfferFetchFailedException("Issuer not trusted by user")
            }
        }
    }
}



