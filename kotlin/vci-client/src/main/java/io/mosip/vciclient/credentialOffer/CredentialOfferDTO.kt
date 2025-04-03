package io.mosip.vciclient.credentialOffer

import com.google.gson.annotations.SerializedName

data class CredentialOffer(
    @SerializedName("credential_issuer")
    val credentialIssuer: String,

    @SerializedName("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,

    @SerializedName("grants")
    val grants: CredentialOfferGrants? = null
)

data class CredentialOfferGrants(
    @SerializedName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedGrant: PreAuthorizedCodeGrant? = null,

    @SerializedName("authorization_code")
    val authorizationCodeGrant: AuthorizationCodeGrant? = null
)

data class PreAuthorizedCodeGrant(
    @SerializedName("pre-authorized_code")
    val preAuthorizedCode: String,

    @SerializedName("tx_code")
    val txCode: TxCode? = null,

    @SerializedName("authorization_server")
    val authorizationServer: String? = null,

    @SerializedName("interval")
    val interval: Int? = null
)

data class TxCode(
    @SerializedName("input_mode")
    val inputMode: String? = null,

    @SerializedName("length")
    val length: Int? = null,

    @SerializedName("description")
    val description: String? = null
)

data class AuthorizationCodeGrant(
    @SerializedName("issuer_state")
    val issuerState: String? = null,

    @SerializedName("authorization_server")
    val authorizationServer: String? = null
)

