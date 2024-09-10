package io.mosip.vciclient.credentialRequest

import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.credentialRequest.types.LdpVcCredentialRequest
import io.mosip.vciclient.credentialRequest.types.MsoMdocCredentialRequest
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.exception.InvalidDataProvidedException
import okhttp3.Request

class CredentialRequestFactory {
    companion object {
        fun createCredentialRequest(
            credentialFormat: CredentialFormat,
            accessToken: String,
            issuerMetaData: IssuerMetaData,
            proof: Proof,
        ): Request {
            when (credentialFormat) {
                CredentialFormat.LDP_VC -> {
                    return validateAndConstructRequest(
                        LdpVcCredentialRequest(
                            accessToken,
                            issuerMetaData,
                            proof
                        )
                    )
                }

                CredentialFormat.MSO_MDOC -> {
                    return validateAndConstructRequest(
                        MsoMdocCredentialRequest(
                            accessToken,
                            issuerMetaData,
                            proof
                        )
                    )
                }
            }
        }

        private fun validateAndConstructRequest(credentialRequest: CredentialRequest): Request {
            val issuerMetaDataValidatorResult = credentialRequest.validateIssuerMetaData()
            if (issuerMetaDataValidatorResult.isValid)
                return credentialRequest.constructRequest()
            throw InvalidDataProvidedException(issuerMetaDataValidatorResult.invalidFields.toString())
        }
    }
}