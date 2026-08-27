package io.mosip.vciclient.issuerMetadata

import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test

class IssuerMetadataResultTest {
    private val credentialConfigurationId = "UniversityDegreeCredential"

    private fun resultWith(credentialConfiguration: Map<String, Any?>): IssuerMetadataResult =
        IssuerMetadataResult(
            issuerMetadata = mockk(relaxed = true),
            raw = mapOf(
                "credential_configurations_supported" to mapOf(
                    credentialConfigurationId to credentialConfiguration
                )
            )
        )

    @Test
    fun `should extract jwt proof signing algorithms`() {
        val result = resultWith(
            mapOf(
                "proof_types_supported" to mapOf(
                    "jwt" to mapOf("proof_signing_alg_values_supported" to listOf("ES256", "RS256"))
                )
            )
        )

        assertEquals(
            listOf("ES256", "RS256"),
            result.extractJwtProofSigningAlgorithms(credentialConfigurationId)
        )
    }

    @Test
    fun `should extract every advertised proof type`() {
        val result = resultWith(
            mapOf(
                "proof_types_supported" to mapOf(
                    "jwt" to mapOf("proof_signing_alg_values_supported" to listOf("ES256")),
                    "attestation" to mapOf("proof_signing_alg_values_supported" to listOf("ES256"))
                )
            )
        )

        assertEquals(
            listOf("jwt", "attestation"),
            result.extractSupportedProofTypes(credentialConfigurationId)
        )
    }

    @Test
    fun `should extract cryptographic binding methods`() {
        val result = resultWith(
            mapOf("cryptographic_binding_methods_supported" to listOf("jwk", "did:key"))
        )

        assertEquals(
            listOf("jwk", "did:key"),
            result.extractCryptographicBindingMethods(credentialConfigurationId)
        )
    }

    @Test
    fun `should return empty lists when the credential configuration omits proof metadata`() {
        val result = resultWith(mapOf("format" to "ldp_vc"))

        assertEquals(emptyList<String>(), result.extractJwtProofSigningAlgorithms(credentialConfigurationId))
        assertEquals(emptyList<String>(), result.extractSupportedProofTypes(credentialConfigurationId))
        assertEquals(emptyList<String>(), result.extractCryptographicBindingMethods(credentialConfigurationId))
    }

    @Test
    fun `should return empty lists when the credential configuration is absent`() {
        val result = resultWith(mapOf("format" to "ldp_vc"))

        assertEquals(emptyList<String>(), result.extractJwtProofSigningAlgorithms("unknown"))
        assertEquals(emptyList<String>(), result.extractSupportedProofTypes("unknown"))
        assertEquals(emptyList<String>(), result.extractCryptographicBindingMethods("unknown"))
    }

    @Test
    fun `should ignore malformed proof metadata instead of throwing`() {
        val result = resultWith(
            mapOf(
                "proof_types_supported" to "jwt",
                "cryptographic_binding_methods_supported" to mapOf("jwk" to true)
            )
        )

        assertEquals(emptyList<String>(), result.extractJwtProofSigningAlgorithms(credentialConfigurationId))
        assertEquals(emptyList<String>(), result.extractSupportedProofTypes(credentialConfigurationId))
        assertEquals(emptyList<String>(), result.extractCryptographicBindingMethods(credentialConfigurationId))
    }
}
