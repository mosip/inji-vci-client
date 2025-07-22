package io.mosip.vciclient.issuerMetadata

data class IssuerMetadataResult(
    var issuerMetadata: IssuerMetadata,
    val raw: Map<String, Any?>,
    val credentialIssuer: String? = null
) {
    fun extractJwtProofSigningAlgorithms(credentialConfigurationId: String): List<String> {
        val configurations = this.raw["credential_configurations_supported"] as? Map<*, *>
        val config = configurations?.get(credentialConfigurationId) as? Map<*, *>
        val proofTypes = config?.get("proof_types_supported") as? Map<*, *>
        val jwt = proofTypes?.get("jwt") as? Map<*, *>
        val jwtProofSigningAlgorithmsSupported = jwt?.get("proof_signing_alg_values_supported") as? List<String>

        return jwtProofSigningAlgorithmsSupported ?: emptyList()
    }
}