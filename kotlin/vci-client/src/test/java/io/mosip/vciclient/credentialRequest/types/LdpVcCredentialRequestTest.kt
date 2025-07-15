package io.mosip.vciclient.credentialRequest.types

import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.credential.request.util.ValidatorResult
import io.mosip.vciclient.proof.jwt.JWTProof
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.credential.request.types.LdpVcCredentialRequest
import okhttp3.Request
import okhttp3.internal.http2.Header
import okhttp3.internal.toHeaderList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI

class LdpVcCredentialRequestTest {
    @Test
    fun `should create JSON in expected format`() {
        val credentialEndpoint = "https://credentialendpoint/"

        val ldpVcRequest: Request = LdpVcCredentialRequest(
            "accessToken",
            IssuerMetadata(
                "/credentialAudience",
                credentialEndpoint,

                credentialType = listOf("VerifiableCredential"),
                credentialFormat = CredentialFormat.LDP_VC
            ), JWTProof("headerEncoded.payloadEncoded.signature")
        ).constructRequest()

        assertTrue(
            ldpVcRequest.headers.toHeaderList().containsAll(
                listOf(
                    Header("Authorization", "Bearer accessToken"),
                    Header("Content-Type", "application/json")
                )
            )
        )
        assertEquals(URI(credentialEndpoint), ldpVcRequest.url.toUri())
        assertEquals("POST", ldpVcRequest.method)
    }

    @Test
    fun `should return isValid as true when required issuerMetadata details are available`() {

        val ldpVcRequest: LdpVcCredentialRequest = LdpVcCredentialRequest(
            "accessToken",
            IssuerMetadata(
                "/credentialAudience",
                "https://credentialendpoint/",

                credentialType = listOf("VerifiableCredential"),
                credentialFormat = CredentialFormat.LDP_VC
            ), JWTProof("headerEncoded.payloadEncoded.signature")
        )

        val validatorResult: ValidatorResult = ldpVcRequest.validateIssuerMetaData()

        assertTrue(validatorResult.isValid)
        assertTrue(validatorResult.invalidFields.isEmpty())
    }

    @Test
    fun `should return validator result with isValid as false & invalidFields when required issuerMetadata details are not available`() {

        val ldpVcRequest = LdpVcCredentialRequest(
            "accessToken",
            IssuerMetadata(
                "/credentialAudience",
                "https://credentialendpoint/",
                credentialFormat = CredentialFormat.LDP_VC,
            ), JWTProof("headerEncoded.payloadEncoded.signature")
        )

        val validatorResult: ValidatorResult = ldpVcRequest.validateIssuerMetaData()

        assertFalse(validatorResult.isValid)
        assertTrue(validatorResult.invalidFields.containsAll(listOf("credentialType")))
    }
}