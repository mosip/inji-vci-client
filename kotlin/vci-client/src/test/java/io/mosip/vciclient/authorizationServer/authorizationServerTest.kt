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
            ex.message.contains("Failed to discover authorization server metadata at both endpoints")
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
            ex.message.contains("Failed to discover authorization server metadata at both endpoints")
        )
    }
}
