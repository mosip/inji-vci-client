package io.mosip.vciclient.dto

import io.mosip.vciclient.constants.CredentialFormat
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.Test

class IssuerMetaDataTest {

    @Test
    fun `should preserve issuer metadata fields`() {
        val issuerMetaData = IssuerMetaData(
            credentialAudience = "https://issuer.example.com",
            credentialEndpoint = "https://issuer.example.com/credential",
            downloadTimeoutInMilliSeconds = 5000,
            credentialType = arrayOf("VerifiableCredential", "UniversityDegreeCredential"),
            credentialFormat = CredentialFormat.JWT_VC_JSON,
            doctype = "org.iso.18013.5.1.mDL",
            claims = mapOf("given_name" to mapOf("mandatory" to true))
        )

        assertEquals("https://issuer.example.com", issuerMetaData.credentialAudience)
        assertEquals(
            "https://issuer.example.com/credential",
            issuerMetaData.credentialEndpoint
        )
        assertEquals(5000, issuerMetaData.downloadTimeoutInMilliSeconds)
        assertContentEquals(
            arrayOf("VerifiableCredential", "UniversityDegreeCredential"),
            issuerMetaData.credentialType
        )
        assertEquals(CredentialFormat.JWT_VC_JSON, issuerMetaData.credentialFormat)
        assertEquals("org.iso.18013.5.1.mDL", issuerMetaData.doctype)
        assertEquals(mapOf("given_name" to mapOf("mandatory" to true)), issuerMetaData.claims)
    }
}
