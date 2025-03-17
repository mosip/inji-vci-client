package io.mosip.vciclient.credentialResponse

import com.google.gson.JsonElement
import io.mosip.vciclient.common.JsonUtils

data class CredentialResponse(
    val credential: JsonElement,
)  {
    fun toJsonString(): String {
        return JsonUtils.serialize(this)
    }
}
