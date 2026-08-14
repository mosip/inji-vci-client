package io.mosip.vciclient.authorizationServer

import com.google.gson.annotations.SerializedName

data class PushedAuthorizationResponse(
    @SerializedName("request_uri")
    val requestUri: String? = null,

    @SerializedName("expires_in")
    val expiresIn: Long? = null,
)
