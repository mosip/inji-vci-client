package io.mosip.vciclient.authorizationServer

import io.mockk.CapturingSlot
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.slot
import io.mockk.unmockkAll
import io.mosip.vciclient.common.JsonUtils
import io.mosip.vciclient.exception.NetworkRequestFailedException
import io.mosip.vciclient.exception.PushedAuthorizationRequestException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.networkManager.NetworkResponse
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows

class PushedAuthorizationRequestServiceTest {

    private val parEndpoint = "https://as.example.com/as/par"
    private val responseBody = """{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}"""

    @Before
    fun setUp() {
        mockkObject(NetworkManager)
        mockkObject(JsonUtils)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun stubSuccessNetwork(bodySlot: CapturingSlot<Map<String, String>>) {
        every {
            NetworkManager.sendRequest(parEndpoint, HttpMethod.POST, any(), capture(bodySlot), any())
        } returns NetworkResponse(responseBody, null)
    }

    private fun stubDeserialize(response: PushedAuthorizationResponse?) {
        every {
            JsonUtils.deserialize(any(), PushedAuthorizationResponse::class.java)
        } returns response
    }

    @Test
    fun `should return request_uri and expires_in on success`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:ietf:params:oauth:request_uri:abc", 90))

        val result = PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid"
        )

        assertEquals("urn:ietf:params:oauth:request_uri:abc", result.requestUri)
        assertEquals(90L, result.expiresIn)
    }

    @Test
    fun `should always include core params including nonce`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid"
        )

        val body = bodySlot.captured
        assertEquals("code", body["response_type"])
        assertEquals("client-id", body["client_id"])
        assertEquals("app://callback", body["redirect_uri"])
        assertEquals("challenge", body["code_challenge"])
        assertEquals("S256", body["code_challenge_method"])
        assertEquals("state-123", body["state"])
        assertEquals("nonce-123", body["nonce"])
    }

    @Test
    fun `should send authorization_details when provided and omit scope`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid",
            authorizationDetails = """[{"type":"openid_credential"}]"""
        )

        val body = bodySlot.captured
        assertEquals("""[{"type":"openid_credential"}]""", body["authorization_details"])
        assertFalse(body.containsKey("scope"))
    }

    @Test
    fun `should send scope when authorization_details is absent`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid"
        )

        val body = bodySlot.captured
        assertEquals("openid", body["scope"])
        assertFalse(body.containsKey("authorization_details"))
    }

    @Test
    fun `should include issuer_state only when present`() = runBlocking {
        val withSlot = slot<Map<String, String>>()
        stubSuccessNetwork(withSlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid",
            issuerState = "issuer-state-xyz"
        )
        assertEquals("issuer-state-xyz", withSlot.captured["issuer_state"])

        val withoutSlot = slot<Map<String, String>>()
        stubSuccessNetwork(withoutSlot)
        PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid"
        )
        assertFalse(withoutSlot.captured.containsKey("issuer_state"))
    }

    @Test
    fun `should merge clientAuthParams into the body`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid",
            clientAuthParams = mapOf(
                "client_assertion_type" to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion" to "signed.jwt.value"
            )
        )

        val body = bodySlot.captured
        assertEquals(
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            body["client_assertion_type"]
        )
        assertEquals("signed.jwt.value", body["client_assertion"])
    }

    @Test
    fun `clientAuthParams must not overwrite core params like client_id`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(PushedAuthorizationResponse("urn:request_uri:abc"))

        PushedAuthorizationRequestService().pushAuthorizationRequest(
            parEndpoint = parEndpoint,
            clientId = "real-client-id",
            redirectUri = "app://callback",
            codeChallenge = "challenge",
            state = "state-123",
            nonce = "nonce-123",
            scope = "openid",
            clientAuthParams = mapOf("client_id" to "malicious-id")
        )

        assertEquals("real-client-id", bodySlot.captured["client_id"])
    }

    @Test
    fun `should throw when neither scope nor authorization_details is provided`() = runBlocking {
        val ex = assertThrows<PushedAuthorizationRequestException> {
            PushedAuthorizationRequestService().pushAuthorizationRequest(
                parEndpoint = parEndpoint,
                clientId = "client-id",
                redirectUri = "app://callback",
                codeChallenge = "challenge",
                state = "state-123",
                nonce = "nonce-123"
            )
        }
        assertTrue(ex.message.contains("scope or authorization_details"))
    }

    @Test
    fun `should throw when response has no request_uri`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        stubSuccessNetwork(bodySlot)
        stubDeserialize(null)

        val ex = assertThrows<PushedAuthorizationRequestException> {
            PushedAuthorizationRequestService().pushAuthorizationRequest(
                parEndpoint = parEndpoint,
                clientId = "client-id",
                redirectUri = "app://callback",
                codeChallenge = "challenge",
                state = "state-123",
                nonce = "nonce-123",
                scope = "openid"
            )
        }
        assertTrue(ex.message.contains("missing request_uri"))
    }

    @Test
    fun `should wrap server error and propagate issuerErrorCode`() = runBlocking {
        val bodySlot = slot<Map<String, String>>()
        every {
            NetworkManager.sendRequest(parEndpoint, HttpMethod.POST, any(), capture(bodySlot), any())
        } throws NetworkRequestFailedException(
            "HTTP 401",
            "invalid_client",
            "Client authentication failed",
            null
        )

        val ex = assertThrows<PushedAuthorizationRequestException> {
            PushedAuthorizationRequestService().pushAuthorizationRequest(
                parEndpoint = parEndpoint,
                clientId = "client-id",
                redirectUri = "app://callback",
                codeChallenge = "challenge",
                state = "state-123",
                nonce = "nonce-123",
                scope = "openid"
            )
        }
        assertEquals("invalid_client", ex.issuerErrorCode)
        assertEquals("Client authentication failed", ex.issuerErrorDescription)
    }
}
