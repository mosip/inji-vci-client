package io.mosip.vciclient.issuerMetadata

data class IssuerMetadataResult(
    var issuerMetadata: IssuerMetadata,
    val raw: Map<String, Any?>,
    val credentialIssuer: String? = null
)