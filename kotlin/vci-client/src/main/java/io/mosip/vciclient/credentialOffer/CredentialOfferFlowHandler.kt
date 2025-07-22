package io.mosip.vciclient.credentialOffer

import io.mosip.vciclient.authorizationCodeFlow.AuthorizationCodeFlowService
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credential.response.CredentialResponse
import io.mosip.vciclient.exception.CredentialOfferFetchFailedException
import io.mosip.vciclient.exception.DownloadFailedException
import io.mosip.vciclient.issuerMetadata.IssuerMetadataService
import io.mosip.vciclient.preAuthCodeFlow.PreAuthCodeFlowService
import io.mosip.vciclient.constants.AuthorizeUserCallback
import io.mosip.vciclient.constants.CheckIssuerTrustCallback
import io.mosip.vciclient.constants.ProofJwtCallback
import io.mosip.vciclient.constants.TokenResponseCallback
import io.mosip.vciclient.constants.TxCodeCallback

class CredentialOfferFlowHandler {

    suspend fun downloadCredentials(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: TxCodeCallback?,
        authorizeUser: AuthorizeUserCallback,
        getTokenResponse: TokenResponseCallback,
        getProofJwt: ProofJwtCallback,
        onCheckIssuerTrust: CheckIssuerTrustCallback? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        val offer = CredentialOfferService().fetchCredentialOffer(credentialOffer)
        if (offer.credentialConfigurationIds.size > 1) {
            throw DownloadFailedException("Batch credential request is not supported.")
        }
        val credentialConfigurationId = offer.credentialConfigurationIds.firstOrNull() ?: ""
        val issuerMetadataResult = IssuerMetadataService().fetchIssuerMetadataResult(
            offer.credentialIssuer,
            credentialConfigurationId
        )

        val issuerDisplay =
            issuerMetadataResult.raw["display"] as? List<Map<String, Any>> ?: listOf(emptyMap())
        ensureIssuerTrust(
            credentialIssuer = offer.credentialIssuer,
            issuerDisplay = issuerDisplay,
            onCheckIssuerTrust = onCheckIssuerTrust
        )

        val credentialResponse = when {
            offer.isPreAuthorizedFlow() -> {
                PreAuthCodeFlowService().requestCredentials(
                    issuerMetadata = issuerMetadataResult.issuerMetadata,
                    jwtProofSigningAlgorithms = issuerMetadataResult.extractJwtProofSigningAlgorithms(
                        credentialConfigurationId
                    ),
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    credentialConfigurationId = credentialConfigurationId,
                    getTxCode = getTxCode,
                    downloadTimeoutInMillis = downloadTimeoutInMillis,
                    offer = offer
                )
            }

            offer.isAuthorizationCodeFlow() -> {
                AuthorizationCodeFlowService().requestCredentials(
                    issuerMetadata = issuerMetadataResult.issuerMetadata,
                    credentialConfigurationId = offer.credentialConfigurationIds.first(),
                    clientMetadata = clientMetadata,
                    authorizeUser = authorizeUser,
                    getTokenResponse = getTokenResponse,
                    getProofJwt = getProofJwt,
                    credentialOffer = offer,
                    downloadTimeOutInMillis = downloadTimeoutInMillis,
                    jwtProofAlgorithmsSupported = issuerMetadataResult.extractJwtProofSigningAlgorithms(
                        credentialConfigurationId
                    )
                )
            }

            else -> {
                throw CredentialOfferFetchFailedException("Credential offer does not contain a supported grant type")
            }
        }
        if (credentialResponse.credential.isJsonNull) {
            throw CredentialOfferFetchFailedException("No credential response found")
        }
        return credentialResponse
    }

    private suspend fun ensureIssuerTrust(
        credentialIssuer: String,
        issuerDisplay: List<Map<String, Any>>,
        onCheckIssuerTrust: CheckIssuerTrustCallback?
    ) {
        if (onCheckIssuerTrust != null) {
            val consented = onCheckIssuerTrust(credentialIssuer, issuerDisplay)
            if (!consented) {
                throw CredentialOfferFetchFailedException("Issuer not trusted by user")
            }
        }
    }
}



