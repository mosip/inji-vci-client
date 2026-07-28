package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request

import com.google.gson.annotations.SerializedName
import io.mosip.vciclient.common.JsonUtils

internal data class IARInitialRequestBody(
    @SerializedName("response_type")
    val responseType: String = "code",

    @SerializedName("client_id")
    val clientId: String,

    @SerializedName("code_challenge")
    val codeChallenge: String,

    @SerializedName("code_challenge_method")
    val codeChallengeMethod: String = "S256",

    @SerializedName("redirect_uri")
    val redirectUri: String,

    @SerializedName("authorization_details")
    val authorizationDetails: List<AuthorizationDetail>,

    @SerializedName("interaction_types_supported")
    val interactionTypesSupported: List<String>,

    @SerializedName("dpop_jkt")
    val dpopJkt: String
) {
    fun toFormMap(): Map<String, String> = mapOf(
        "response_type" to responseType,
        "client_id" to clientId,
        "code_challenge" to codeChallenge,
        "code_challenge_method" to codeChallengeMethod,
        "redirect_uri" to redirectUri,
        "authorization_details" to JsonUtils.serialize(authorizationDetails),
        "interaction_types_supported" to interactionTypesSupported.joinToString(","),
        "dpop_jkt" to dpopJkt
    )
}


