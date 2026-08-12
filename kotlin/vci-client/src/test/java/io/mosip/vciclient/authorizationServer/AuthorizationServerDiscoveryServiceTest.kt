package io.mosip.vciclient.authorizationServer

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.exception.AuthorizationServerDiscoveryException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class AuthorizationServerDiscoveryServiceTest {

    private val baseUrl = "https://example.com"
    private val oauthUrl = "$baseUrl/.well-known/oauth-authorization-server"
    private val openidUrl = "$baseUrl/.well-known/openid-configuration"
    private val mockResponseBody = """{"authorization_endpoint":"https://example.com/auth"}"""

    @Before
    fun setUp() {
        mockkObject(NetworkManager)
        mockkObject(JsonUtils)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should return metadata when oauth discovery succeeds`() = runBlocking {
        val expected = AuthorizationServerMetadata(
            issuer = "example", authorizationEndpoint = "https://example.com/auth"
        )

        every {
            NetworkManager.sendRequest(oauthUrl, HttpMethod.GET, any(), any(), 10000)
        } returns io.mosip.vciclient.networkManager.NetworkResponse(mockResponseBody, null)

        every {
            JsonUtils.deserialize(
                mockResponseBody, AuthorizationServerMetadata::class.java
            )
        } returns expected

        val result = AuthorizationServerDiscoveryService().discover(baseUrl)
        assertEquals(expected.authorizationEndpoint, result.authorizationEndpoint)
    }

    @Test
    fun `should return metadata when oauth fails and openid succeeds`() = runBlocking {
        val expected = AuthorizationServerMetadata(
            issuer = "example", authorizationEndpoint = "https://example.com/auth"
        )

        every {
            NetworkManager.sendRequest(oauthUrl, HttpMethod.GET, any(), any(), 10000)
        } throws RuntimeException("Simulated failure")

        every {
            NetworkManager.sendRequest(openidUrl, HttpMethod.GET, any(), any(), 10000)
        } returns io.mosip.vciclient.networkManager.NetworkResponse(mockResponseBody, null)

        every {
            JsonUtils.deserialize(
                mockResponseBody, AuthorizationServerMetadata::class.java
            )
        } returns expected

        val result = AuthorizationServerDiscoveryService().discover(baseUrl)
        assertEquals(expected.authorizationEndpoint, result.authorizationEndpoint)
    }

    @Test
    fun `should throw exception when both discovery endpoints fail`() = runBlocking {
        every {
            NetworkManager.sendRequest(oauthUrl, HttpMethod.GET, any(), any(), 10000)
        } throws RuntimeException("OAuth down")

        every {
            NetworkManager.sendRequest(openidUrl, HttpMethod.GET, any(), any(), 10000)
        } throws RuntimeException("OpenID down")

        val ex = assertThrows<AuthorizationServerDiscoveryException> {
            AuthorizationServerDiscoveryService().discover(baseUrl)
        }

        assertTrue(
            ex.message.contains("Failed to discover authorization server metadata at all well-known endpoints")
        )
    }

    @Test
    fun `should throw exception when both responses are empty`() = runBlocking {
        every {
            NetworkManager.sendRequest(oauthUrl, HttpMethod.GET, any(), any(), 10000)
        } returns io.mosip.vciclient.networkManager.NetworkResponse("", null)

        every {
            NetworkManager.sendRequest(openidUrl, HttpMethod.GET, any(), any(), 10000)
        } returns io.mosip.vciclient.networkManager.NetworkResponse("", null)

        val ex = assertThrows<AuthorizationServerDiscoveryException> {
            AuthorizationServerDiscoveryService().discover(baseUrl)
        }

        assertTrue(
            ex.message.contains("Failed to discover authorization server metadata at all well-known endpoints")
        )
    }

    @Test
    fun `buildCandidateWellKnownUrls inserts suffix before path per RFC 8414 for path-based issuer`() {
        val candidates = AuthorizationServerDiscoveryService()
            .buildCandidateWellKnownUrls("https://host.example.com/v1/esignet")

        assertEquals(
            listOf(
                "https://host.example.com/.well-known/oauth-authorization-server/v1/esignet",
                "https://host.example.com/.well-known/openid-configuration/v1/esignet",
                "https://host.example.com/v1/esignet/.well-known/oauth-authorization-server",
                "https://host.example.com/v1/esignet/.well-known/openid-configuration"
            ),
            candidates
        )
    }

    @Test
    fun `buildCandidateWellKnownUrls only appends when issuer has no path`() {
        val candidates = AuthorizationServerDiscoveryService()
            .buildCandidateWellKnownUrls("https://host.example.com")

        assertEquals(
            listOf(
                "https://host.example.com/.well-known/oauth-authorization-server",
                "https://host.example.com/.well-known/openid-configuration"
            ),
            candidates
        )
    }

    @Test
    fun `buildCandidateWellKnownUrls preserves port and trims trailing slash`() {
        val candidates = AuthorizationServerDiscoveryService()
            .buildCandidateWellKnownUrls("https://host.example.com:8443/tenant/")

        assertTrue(
            candidates.contains("https://host.example.com:8443/.well-known/oauth-authorization-server/tenant")
        )
        assertTrue(
            candidates.contains("https://host.example.com:8443/tenant/.well-known/oauth-authorization-server")
        )
    }

    @Test
    fun `discover uses RFC 8414 inserted well-known url for path-based issuer`() = runBlocking {
        val issuer = "https://host.example.com/v1/esignet"
        val insertedOauthUrl =
            "https://host.example.com/.well-known/oauth-authorization-server/v1/esignet"
        val expected = AuthorizationServerMetadata(
            issuer = "x", authorizationEndpoint = "https://host.example.com/auth"
        )

        every {
            NetworkManager.sendRequest(insertedOauthUrl, HttpMethod.GET, any(), any(), 10000)
        } returns io.mosip.vciclient.networkManager.NetworkResponse(mockResponseBody, null)

        every {
            JsonUtils.deserialize(mockResponseBody, AuthorizationServerMetadata::class.java)
        } returns expected

        val result = AuthorizationServerDiscoveryService().discover(issuer)
        assertEquals(expected.authorizationEndpoint, result.authorizationEndpoint)
    }

    @Test
    fun `discover falls back to legacy appended well-known url for path-based issuer`() = runBlocking {
        val issuer = "https://host.example.com/v1/esignet"
        val insertedOauthUrl =
            "https://host.example.com/.well-known/oauth-authorization-server/v1/esignet"
        val insertedOpenidUrl =
            "https://host.example.com/.well-known/openid-configuration/v1/esignet"
        val legacyOauthUrl =
            "https://host.example.com/v1/esignet/.well-known/oauth-authorization-server"
        val expected = AuthorizationServerMetadata(
            issuer = "x", authorizationEndpoint = "https://host.example.com/auth"
        )

        every {
            NetworkManager.sendRequest(insertedOauthUrl, HttpMethod.GET, any(), any(), 10000)
        } throws RuntimeException("inserted oauth down")

        every {
            NetworkManager.sendRequest(insertedOpenidUrl, HttpMethod.GET, any(), any(), 10000)
        } throws RuntimeException("inserted openid down")

        every {
            NetworkManager.sendRequest(legacyOauthUrl, HttpMethod.GET, any(), any(), 10000)
        } returns io.mosip.vciclient.networkManager.NetworkResponse(mockResponseBody, null)

        every {
            JsonUtils.deserialize(mockResponseBody, AuthorizationServerMetadata::class.java)
        } returns expected

        val result = AuthorizationServerDiscoveryService().discover(issuer)
        assertEquals(expected.authorizationEndpoint, result.authorizationEndpoint)
    }
}
