package io.mosip.vciclient.credentialRequest

import io.mosip.vciclient.credentialRequest.util.ValidatorResult
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import okhttp3.Request

interface CredentialRequest {
    val accessToken: String
    val issuerMetadata: IssuerMetadata
    val proof: Proof

    fun constructRequest(): Request
    fun validateIssuerMetaData(): ValidatorResult
}