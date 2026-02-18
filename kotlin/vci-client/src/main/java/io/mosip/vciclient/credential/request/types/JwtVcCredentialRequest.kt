package io.mosip.vciclient.credential.request.types

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.constants.Constants.APPLICATION_JSON
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.credential.request.CredentialRequest
import io.mosip.vciclient.credential.request.util.ValidatorResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import io.mosip.vciclient.exception.InvalidDataProvidedException
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody

class JwtVcCredentialRequest(
    override val accessToken: String,
    override val issuerMetadata: IssuerMetadata,
    override val proof: Proof,
) : CredentialRequest {

    override fun constructRequest(): Request {
        return Request.Builder()
            .url(issuerMetadata.credentialEndpoint!!)
            .addHeader("Authorization", "Bearer $accessToken")
            .addHeader(CONTENT_TYPE, APPLICATION_JSON)
            .post(generateRequestBody())
            .build()
    }

    override fun validateIssuerMetaData(): ValidatorResult {
        val validatorResult = ValidatorResult()
        if (issuerMetadata.credentialEndpoint.isNullOrEmpty()) {
            validatorResult.addInvalidField("credentialEndpoint")
        }
        if (issuerMetadata.credentialType.isNullOrEmpty()) {
            validatorResult.addInvalidField("credentialType")
        }
        return validatorResult
    }

    private fun generateRequestBody(): RequestBody {
        val definition = JwtVcCredentialDefinition(
            type = issuerMetadata.credentialType ?: throw InvalidDataProvidedException("Credential type is missing in issuer metadata")
        )
        val request = JwtVcRequestBody(
            format = issuerMetadata.credentialFormat.value,
            credential_definition = definition,
            proof = proof
        ).toJson()
        return request.toRequestBody(APPLICATION_JSON.toMediaTypeOrNull())
    }
}

private data class JwtVcCredentialDefinition(
    val type: List<String>
)

private data class JwtVcRequestBody(
    val format: String,
    val credential_definition: JwtVcCredentialDefinition,
    val proof: Proof
) {
    fun toJson(): String = JsonUtils.serialize(this)
}
