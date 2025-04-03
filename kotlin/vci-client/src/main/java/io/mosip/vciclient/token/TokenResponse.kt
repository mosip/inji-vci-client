package io.mosip.vciclient.token

import com.google.gson.annotations.SerializedName

data class TokenResponse(
    @SerializedName("access_token")
    val accessToken: String,

    @SerializedName("token_type")
    val tokenType: String,

    @SerializedName("expires_in")
    val expiresIn: Int? = null,

    @SerializedName("c_nonce")
    val cNonce: String? = null,

    @SerializedName("c_nonce_expires_in")
    val cNonceExpiresIn: Int? = null
)
