package io.mosip.vciclient.credential.request.types

import android.util.Log
import com.google.gson.annotations.SerializedName
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.credential.request.CredentialRequest
import io.mosip.vciclient.credential.request.util.ValidatorResult
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody

class LdpVcCredentialRequest(
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
        if(issuerMetadata.credentialType.isNullOrEmpty()){
            validatorResult.addInvalidField("credentialType")
        }
        return validatorResult
    }

    private fun generateRequestBody(): RequestBody {
        val credentialRequestBody = CredentialRequestBody(
            credentialDefinition = CredentialDefinition(type = this.issuerMetadata.credentialType!!, context = this.getCredentialRequestContext()),
            proof = proof,
            format = this.issuerMetadata.credentialFormat.value
        ).toJson()
        return credentialRequestBody
            .toRequestBody("application/json".toMediaTypeOrNull())
    }

    private fun getCredentialRequestContext(): List<String> {
       return this.issuerMetadata.context ?: listOf("https://www.w3.org/2018/credentials/v1")
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
    val context: List<String>,
    val type: List<String>,
)