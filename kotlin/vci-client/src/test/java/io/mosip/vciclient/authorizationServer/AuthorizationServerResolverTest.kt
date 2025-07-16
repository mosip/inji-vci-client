package io.mosip.vciclient.authorizationServer

import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import io.mosip.vciclient.credentialOffer.CredentialOffer
import io.mosip.vciclient.credentialOffer.CredentialOfferGrants
import io.mosip.vciclient.credentialOffer.PreAuthCodeGrant
import io.mosip.vciclient.exception.AuthorizationServerDiscoveryException
import io.mosip.vciclient.issuerMetadata.IssuerMetadata
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class AuthorizationServerResolverTest {

    private val credentialIssuer = "https://issuer.example.com"
    private val resolvedMeta = mockk<IssuerMetadata>(relaxed = true)
    private val offer = mockk<CredentialOffer>(relaxed = true)
    private val metadataWithAuth = AuthorizationServerMetadata(
        issuer = "https://auth.single.com",
        authorizationEndpoint = "https://auth.example.com"
    )
    private val metadataWithPreAuth = AuthorizationServerMetadata(
        issuer = "https://preauth.com",
        authorizationEndpoint = "https://auth.example.com"
    )
    private val metadataWithIssuer = AuthorizationServerMetadata(
        issuer = "https://issuer.example.com",
        authorizationEndpoint = "https://auth.example.com"
    )

    @Before
    fun setup() {
        mockkConstructor(AuthorizationServerDiscoveryService::class)
    }

    @After
    fun teardown() = unmockkAll()

    @Test
    fun `should resolve single auth server from metadata`() = runBlocking {
        every { resolvedMeta.authorizationServers } returns listOf("https://auth.single.com")
        every { resolvedMeta.credentialIssuer } returns credentialIssuer

        coEvery { anyConstructed<AuthorizationServerDiscoveryService>().discover("https://auth.single.com") } returns metadataWithAuth

        val result = AuthorizationServerResolver().resolveForAuthCode(resolvedMeta, offer)
        assertEquals("https://auth.example.com", result.authorizationEndpoint)
    }

    @Test
    fun `should resolve auth server from offer's preAuth grant`() = runBlocking {
        every { resolvedMeta.authorizationServers } returns listOf("https://ignored.com","https://preauth.com")
        every { resolvedMeta.credentialIssuer } returns credentialIssuer

        every {
            offer.grants
        } returns CredentialOfferGrants(
            preAuthorizedGrant = PreAuthCodeGrant("abc", null, "https://preauth.com"),
            authorizationCodeGrant = null
        )

        coEvery { anyConstructed<AuthorizationServerDiscoveryService>().discover("https://preauth.com") } returns metadataWithPreAuth

        val result = AuthorizationServerResolver().resolveForPreAuth(resolvedMeta, offer)
        assertEquals("https://auth.example.com", result.authorizationEndpoint)
    }

    @Test
    fun `should fallback to credential-issuer when no auth server list is present`() = runBlocking {
        every { resolvedMeta.authorizationServers } returns null
        every { resolvedMeta.credentialIssuer } returns credentialIssuer

        coEvery { anyConstructed<AuthorizationServerDiscoveryService>().discover(credentialIssuer) } returns metadataWithIssuer

        val result = AuthorizationServerResolver().resolveForAuthCode(resolvedMeta)
        assertEquals("https://auth.example.com", result.authorizationEndpoint)
    }

    @Test
    fun `should resolve first valid from multiple auth servers`() = runBlocking {
        every { resolvedMeta.authorizationServers } returns listOf(
            "https://fail.com",
            "https://auth.single.com"
        )
        every { resolvedMeta.credentialIssuer } returns credentialIssuer

        coEvery { anyConstructed<AuthorizationServerDiscoveryService>().discover("https://fail.com") } throws RuntimeException(
            "fail"
        )
        coEvery { anyConstructed<AuthorizationServerDiscoveryService>().discover("https://auth.single.com") } returns metadataWithAuth

        val result = AuthorizationServerResolver().resolveForAuthCode(resolvedMeta, offer)
        assertEquals("https://auth.example.com", result.authorizationEndpoint)
    }

    @Test
    fun `should throw if none of the multiple auth servers succeed`() = runBlocking {
        every { resolvedMeta.authorizationServers } returns listOf(
            "https://fail1.com",
            "https://fail2.com"
        )
        every { resolvedMeta.credentialIssuer } returns credentialIssuer

        coEvery { anyConstructed<AuthorizationServerDiscoveryService>().discover(any()) } throws RuntimeException(
            "fail"
        )

        val ex = assertThrows<AuthorizationServerDiscoveryException> {
            AuthorizationServerResolver().resolveForAuthCode(resolvedMeta, offer)
        }

        assert(ex.message.contains("None of the authorization servers responded"))
    }

    @Test
    fun `should throw if authorization endpoint is missing`() = runBlocking {
        every { resolvedMeta.authorizationServers } returns listOf("https://empty.com")
        every { resolvedMeta.credentialIssuer } returns credentialIssuer

        val badMetadata = AuthorizationServerMetadata(issuer = "https://empty.com", authorizationEndpoint = null)
        coEvery { anyConstructed<AuthorizationServerDiscoveryService>().discover("https://empty.com") } returns badMetadata

        val ex = assertThrows<AuthorizationServerDiscoveryException> {
            AuthorizationServerResolver().resolveForAuthCode(resolvedMeta, offer)
        }

        assert(ex.message.contains("Missing authorization_endpoint"))
    }
}
