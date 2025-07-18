package io.mosip.vciclient.credential.response

import com.google.gson.JsonElement
import com.google.gson.annotations.SerializedName
import io.mosip.vciclient.common.JsonUtils

data class CredentialResponse(
    val credential: JsonElement,

    @SerializedName("credentialConfigurationId")
    var credentialConfigurationId: String,

    @SerializedName("credentialIssuer")
    var credentialIssuer: String
)  {
    fun toJsonString(): String {
        return JsonUtils.serialize(this)
    }
}
