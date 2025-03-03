package io.mosip.vciclient.credentialResponse.types.ldpVc

import com.google.gson.JsonElement
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.credentialResponse.CredentialResponse

data class LdpVcCredentialResponse(private val credential: JsonElement) : CredentialResponse {
    override fun toJsonString(): String {
        return JsonUtils.serialize(this)
    }
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LdpVcCredentialResponse

        if (credential != other.credential) return false

        return true
    }

    override fun hashCode(): Int {
        val result = 31  + credential.hashCode()
        return result
    }
}
