package io.mosip.vciclient.issuerMetadata

data class IssuerMetadataResult(
    val issuerMetadata: IssuerMetadata,
    val raw: Map<String, Any>
)