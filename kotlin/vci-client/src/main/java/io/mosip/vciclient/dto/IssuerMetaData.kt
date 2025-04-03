package io.mosip.vciclient.dto

import io.mosip.vciclient.constants.CredentialFormat

data class IssuerMetaData(
    val credentialAudience: String,
    val credentialEndpoint: String,
    val downloadTimeoutInMilliSeconds: Int,
    val credentialType: Array<String>? = null,
    val context: Array<String>?=null,
    val credentialFormat: CredentialFormat,
    val doctype: String? = null,
    val claims: Map<String, Any>? = null,
    val preAuthorizedCode:String? = null,
    val tokenEndpoint: String? = null
    )

