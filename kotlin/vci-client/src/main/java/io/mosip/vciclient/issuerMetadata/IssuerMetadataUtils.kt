fun extractProofSigningAlgorithms(
    rawIssuerMetadata: Map<String, Any>,
    credentialConfigurationId: String
): List<String> {
    val configurations = rawIssuerMetadata["credential_configurations_supported"] as? Map<String, Any>
    val config = configurations?.get(credentialConfigurationId) as? Map<String, Any>
    val proofTypes = config?.get("proof_types_supported") as? Map<String, Any>
    val jwt = proofTypes?.get("jwt") as? Map<String, Any>
    val algos = jwt?.get("proof_signing_alg_values_supported") as? List<String>

    return algos ?: emptyList()
}