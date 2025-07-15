package io.mosip.vciclient.credential.response

import com.google.gson.JsonElement
import io.mosip.vciclient.common.JsonUtils

data class CredentialResponse(
    val credential: JsonElement,
    var credentialConfigurationId: String,
    var credentialIssuer: String
)  {
    fun toJsonString(): String {
        return JsonUtils.serialize(this)
    }
}
