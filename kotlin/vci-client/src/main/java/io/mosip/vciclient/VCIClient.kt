package io.mosip.vciclient

import android.content.Context
import io.mosip.vciclient.clientMetadata.ClientMetadata
import io.mosip.vciclient.constants.Constants
import io.mosip.vciclient.credentialRequestFlowHandlers.CredentialOfferHandler
import io.mosip.vciclient.credentialRequestFlowHandlers.TrustedIssuerHandler
import io.mosip.vciclient.credentialResponse.CredentialResponse
import io.mosip.vciclient.exception.VCIClientException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.trustedIssuersManager.TrustedIssuerRegistry


class VCIClient(private val traceabilityId: String?, context: Context) {

    private var trustedIssuerRegistry = TrustedIssuerRegistry(context = context.applicationContext)
    suspend fun requestCredentialByCredentialOffer(
        credentialOffer: String,
        clientMetadata: ClientMetadata,
        getTxCode: (suspend (inputMode: String?, description: String?, length: Int?) -> String)?,
        getProofJwt: suspend (accessToken: String, cNonce: String?, issuerMetadata: Map<String, *>?, credentialConfigurationId: String?) -> String,
        getAuthCode: suspend (authorisationEndpoint: String) -> String,
        onCheckIssuerTrust: (suspend (issuerMetadata: Map<String, Any>) -> Boolean)? = null,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse {
        try {
            return CredentialOfferHandler().downloadCredentials(
                credentialOffer,
                clientMetadata,
                getTxCode,
                getProofJwt,
                getAuthCode,
                onCheckIssuerTrust,
                downloadTimeoutInMillis,
                traceabilityId,
                trustedIssuerRegistry
            )
        } catch (e: VCIClientException) {
            throw e
        } catch (e: Exception) {
            throw VCIClientException("VCI-010", "Unknown Exception - ${e.message}")
        }
    }

    suspend fun requestCredentialFromTrustedIssuer(
        issuerMetadata: IssuerMetadata,
        clientMetadata: ClientMetadata,
        getProofJwt: suspend (
            accessToken: String,
            cNonce: String?,
            issuerMetadata: Map<String, *>?,
            credentialConfigurationId: String?,
        ) -> String,
        getAuthCode: suspend (authorizationEndpoint: String) -> String,
        downloadTimeoutInMillis: Long = Constants.DEFAULT_NETWORK_TIMEOUT_IN_MILLIS,
    ): CredentialResponse? {
        try {
            return TrustedIssuerHandler().downloadCredentials(
                resolvedMeta = issuerMetadata,
                clientMetadata = clientMetadata,
                getProofJwt = getProofJwt,
                getAuthCode = getAuthCode,
                downloadTimeOutInMillis = downloadTimeoutInMillis,
                traceabilityId = traceabilityId
            )
        } catch (e: VCIClientException) {
            throw e
        } catch (e: Exception) {
            throw VCIClientException("VCI-010", "Unknown Exception - ${e.message}")
        }

    }
}
