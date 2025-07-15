package io.mosip.vciclient.credential.request.types

import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.credential.request.CredentialRequest
import io.mosip.vciclient.credential.request.util.ValidatorResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody

class MsoMdocCredentialRequest(
    override val accessToken: String,
    override val issuerMetadata: IssuerMetadata,
    override val proof: Proof,
) : CredentialRequest {
    override fun constructRequest(): Request {
        return Request.Builder()
            .url(this.issuerMetadata.credentialEndpoint)
            .addHeader("Authorization", "Bearer ${this.accessToken}")
            .addHeader("Content-Type", "application/json")
            .post(generateRequestBody())
            .build()
    }

    override fun validateIssuerMetaData(): ValidatorResult {
        val validatorResult = ValidatorResult()
        if (issuerMetadata.doctype.isNullOrEmpty()) {
            validatorResult.addInvalidField("doctype")
        }
        return validatorResult
    }

    private fun generateRequestBody(): RequestBody {
        val credentialRequestBody = MdocCredentialRequestBody(
            claims = issuerMetadata.claims,
            proof = proof,
            format = this.issuerMetadata.credentialFormat.value,
            doctype = issuerMetadata.doctype!!
        ).toJson()
        return credentialRequestBody
            .toRequestBody("application/json".toMediaTypeOrNull())
    }
}

private data class MdocCredentialRequestBody(
    val format: String,
    val doctype: String,
    val claims: Map<String, Any>? = null,
    val proof: Proof,
) {
    fun toJson(): String {
        return JsonUtils.serialize(this)
    }
}