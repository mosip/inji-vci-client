package io.mosip.vciclient.credential.request

import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.exception.InvalidDataProvidedException
import io.mosip.vciclient.proof.jwt.JWTProof
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test

class CredentialRequestFactoryDraft13Test {
    @Test
    fun `should throw exception when required details are not available in Issuer metadata based on VC format`() {
        val factory = CredentialRequestFactoryDraft13()

        assertThrows(
            InvalidDataProvidedException::class.java,
        ) {
            factory.createCredentialRequest(
                CredentialFormat.MSO_MDOC, "access-token",
                IssuerMetadata(
                    "/credentialAudience",
                    "https://credentialendpoint/",
                    credentialFormat = CredentialFormat.LDP_VC,
                ), JWTProof("headerEncoded.payloadEncoded.signature")
            )
        }
        assertThrows(
            InvalidDataProvidedException::class.java,
        ) {
            factory.createCredentialRequest(
                CredentialFormat.MSO_MDOC, "access-token",
                IssuerMetadata(
                    "/credentialAudience",
                    "https://credentialendpoint/",
                    listOf("Uni"),
                    credentialFormat = CredentialFormat.MSO_MDOC,
                    claims = mapOf("org.iso.18013.5.1" to mapOf("given_name" to emptyMap<String, Any>())),
                ), JWTProof("headerEncoded.payloadEncoded.signature")
            )
        }
        assertThrows(
            InvalidDataProvidedException::class.java,
        ) {
            factory.createCredentialRequest(
                CredentialFormat.VC_SD_JWT, "access-token",
                IssuerMetadata(
                    "/credentialAudience",
                    "https://credentialendpoint/",
                    credentialFormat = CredentialFormat.VC_SD_JWT,
                    claims = mapOf("name" to "Alice") // vct missing
                ), JWTProof("headerEncoded.payloadEncoded.signature")
            )
        }
    }

}
