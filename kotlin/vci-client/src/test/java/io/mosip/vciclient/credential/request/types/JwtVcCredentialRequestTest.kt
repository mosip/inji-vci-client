package io.mosip.vciclient.credential.request.types

import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import io.mosip.vciclient.constants.Constants.APPLICATION_JSON
import io.mosip.vciclient.constants.Constants.CONTENT_TYPE
import io.mosip.vciclient.constants.CredentialFormat
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import io.mosip.vciclient.proof.Proof
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import okio.Buffer

class JwtVcCredentialRequestTest {

    private val sampleAccessToken = "test-access-token"
    private val sampleCredentialEndpoint = "https://issuer.example.com/credential"
    private val sampleTypes = listOf("VerifiableCredential", "UniversityDegreeCredential")

    private lateinit var sampleProof: Proof
    private lateinit var issuerMetadata: IssuerMetadata

    @Before
    fun setUp() {
        sampleProof = mockk(relaxed = true)
        issuerMetadata = mockk(relaxed = true)

        every { issuerMetadata.credentialEndpoint } returns sampleCredentialEndpoint
        every { issuerMetadata.credentialType } returns sampleTypes
        every { issuerMetadata.credentialFormat } returns CredentialFormat.JWT_VC_JSON
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `constructRequest should build a valid POST request with correct body JSON`() {
        val request = JwtVcCredentialRequest(
            accessToken = sampleAccessToken,
            issuerMetadata = issuerMetadata,
            proof = sampleProof
        ).constructRequest()

        assertEquals(sampleCredentialEndpoint, request.url.toString())
        assertEquals("POST", request.method)
        assertEquals("Bearer $sampleAccessToken", request.header("Authorization"))
        assertEquals(APPLICATION_JSON, request.header(CONTENT_TYPE))
        assertNotNull(request.body)

        val buffer = Buffer()
        request.body!!.writeTo(buffer)
        val requestBodyString = buffer.readUtf8()

        assertTrue(requestBodyString.contains("credential_definition"))
        assertTrue(requestBodyString.contains("format"))
        assertTrue(requestBodyString.contains("proof"))
    }

    @Test
    fun `validateIssuerMetaData should return valid when credentialType is present`() {
        val validatorResult = JwtVcCredentialRequest(
            accessToken = sampleAccessToken,
            issuerMetadata = issuerMetadata,
            proof = sampleProof
        ).validateIssuerMetaData()

        assertTrue(validatorResult.isValid)
    }

    @Test
    fun `validateIssuerMetaData should return invalid when credentialType is null`() {
        every { issuerMetadata.credentialType } returns null

        val validatorResult = JwtVcCredentialRequest(
            accessToken = sampleAccessToken,
            issuerMetadata = issuerMetadata,
            proof = sampleProof
        ).validateIssuerMetaData()

        assertFalse(validatorResult.isValid)
        assertTrue(validatorResult.invalidFields.contains("credentialType"))
    }

    @Test
    fun `validateIssuerMetaData should return invalid when credentialType is empty`() {
        every { issuerMetadata.credentialType } returns emptyList()

        val validatorResult = JwtVcCredentialRequest(
            accessToken = sampleAccessToken,
            issuerMetadata = issuerMetadata,
            proof = sampleProof
        ).validateIssuerMetaData()

        assertFalse(validatorResult.isValid)
        assertTrue(validatorResult.invalidFields.contains("credentialType"))
    }
}
