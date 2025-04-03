package io.mosip.vciclient.credentialRequest.types

import com.google.gson.annotations.SerializedName
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.credentialRequest.CredentialRequest
import io.mosip.vciclient.credentialRequest.util.ValidatorResult
import io.mosip.vciclient.dto.IssuerMetaData
import io.mosip.vciclient.proof.Proof
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody

class LdpVcCredentialRequest(
    override val accessToken: String,
    override val issuerMetaData: IssuerMetaData,
    override val proof: Proof,
) : CredentialRequest {
    override fun constructRequest(): Request {
        return Request.Builder()
            .url(this.issuerMetaData.credentialEndpoint)
            .addHeader("Authorization", "Bearer ${this.accessToken}")
            .addHeader("Content-Type", "application/json")
            .post(generateRequestBody())
            .build()
    }

    override fun validateIssuerMetaData(): ValidatorResult {
        val validatorResult = ValidatorResult()
        if(issuerMetaData.credentialType.isNullOrEmpty()){
            validatorResult.addInvalidField("credentialType")
        }
        return validatorResult
    }

    private fun generateRequestBody(): RequestBody {
        val credentialRequestBody = CredentialRequestBody(
            credentialDefinition = CredentialDefinition(type = this.issuerMetaData.credentialType!!, context = this.getCredentialRequestContext()),
            proof = proof,
            format = this.issuerMetaData.credentialFormat.value
        ).toJson()

        return credentialRequestBody
            .toRequestBody("application/json".toMediaTypeOrNull())
    }

    private fun getCredentialRequestContext(): Array<String> {
       return this.issuerMetaData.context ?: arrayOf("https://www.w3.org/2018/credentials/v1")
    }
}

private data class CredentialRequestBody(
    val format: String,
    val credentialDefinition: CredentialDefinition,
    val proof: Proof,
) {
    fun toJson(): String {
        return JsonUtils.serialize(this)
    }
}

private data class CredentialDefinition(
    @SerializedName("@context")
    val context: Array<String>? = arrayOf("https://www.w3.org/2018/credentials/v1"),
    val type: Array<String>,
)