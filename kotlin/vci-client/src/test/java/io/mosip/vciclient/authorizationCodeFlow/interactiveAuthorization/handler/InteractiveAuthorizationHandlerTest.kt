package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler

import kotlin.test.assertTrue
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mosip.vciclient.authorizationCodeFlow.AuthorizationMethod
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance.PresentationDuringIssuanceAuthorizationMethodService
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.presentationDuringIssuance.PresentationDuringIssuanceRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.response.AuthorizationResponse
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.networkManager.HttpMethod
import io.mosip.vciclient.networkManager.NetworkManager
import io.mosip.vciclient.networkManager.NetworkResponse
import io.mosip.vciclient.pkce.PKCESessionManager
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import android.util.Base64
import kotlin.test.assertFailsWith


class InteractiveAuthorizationHandlerTest {

    private lateinit var handler: InteractiveAuthorizationHandler

    private val endpoint = "https://issuer.example.com/iar"
    private val credentialConfigId = "cred-config-id"

    private val mapSlot = slot<Map<String, String>>()

    private val clientMetadata = ClientMetadata(
        clientId = "wallet-client",
        redirectUri = "wallet://callback"
    )

    private val pkceSession = PKCESessionManager.PKCESession(
        codeVerifier = "verifier",
        codeChallenge = "challenge",
        state = "state",
        nonce = "nonce"
    )

    val mockPresentationInteractionResponse =
        """ { "status": "require_interaction", "type": "openid4vp_presentation", "auth_session": "mock-auth-session", "openid4vp_request": { "issuer": "https://example.org", "credential_type": "example-vc", "response_type": "vp_token", "response_mode": "iar-post", "nonce": "n-0S6_WzA2Mj", "presentation_definition": { "id": "pd-id", "input_descriptors": [ { "id": "id-1", "schema": [ { "uri": "https://example.org/schema" } ], "constraints": { "fields": [ { "path": ["$.credentialSubject.age"], "filter": { "type": "number", "minimum": 18 } } ] } } ] } } } """.trimIndent()

    @Before
    fun setup() {
        handler = InteractiveAuthorizationHandler()
        mockkObject(NetworkManager)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }


    @Test
    fun `should handle OpenID4VP presentation interaction successfully`() = runTest {
        val responseBody = mockPresentationInteractionResponse

        // OpenID4VP constructor uses android.util.Base64; stub it in JVM unit tests.
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any<ByteArray>(), any()) } returns "b64"

        every {
            NetworkManager.sendRequest(
                url = endpoint,
                method = HttpMethod.POST,
                bodyParams = any(),
                headers = any()
            )
        } returns NetworkResponse(responseBody, null)

        val expectedAuthResponse = mockk<AuthorizationResponse>()

        val presentationMethod = AuthorizationMethod.PresentationDuringIssuance(
            selectCredentialsForPresentation = mockk(relaxed = true),
            signVerifiablePresentation = mockk(relaxed = true),
        )

        mockkConstructor(PresentationDuringIssuanceAuthorizationMethodService::class)
        coEvery {
            anyConstructed<PresentationDuringIssuanceAuthorizationMethodService>()
                .authorizeUser(any<PresentationDuringIssuanceRequestData>())
        } returns expectedAuthResponse

        val result = handler.handle(
            endpoint = endpoint,
            clientMetadata = clientMetadata,
            credentialConfigurationId = credentialConfigId,
            authorizationMethods = listOf(presentationMethod),
            pkceSession = pkceSession,
            traceabilityId = "demo"
        )

        assertEquals(expectedAuthResponse, result)
    }


    @Test
    fun `should throw error for unsupported interaction type`() = runTest {
        val responseBody = """{ "type": "unknown_type" }"""

        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } returns NetworkResponse(responseBody, null)

        val ex = assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                emptyList(),
                pkceSession
            )
        }

        assert(ex.message.contains("No supported interaction types found"))
    }

    @Test
    fun `should throw error when interaction type is missing`() = runTest {
        val responseBody = """{ }"""

        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } returns NetworkResponse(responseBody, null)

        assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                emptyList(),
                pkceSession
            )
        }
    }

    @Test
    fun `should surface authorization server error details from interaction response`() = runTest {
        val responseBody =
            """{ "error": "access_denied", "error_description": "user cancelled the flow" }"""

        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } returns NetworkResponse(responseBody, null)

        val ex = assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                listOf(
                    AuthorizationMethod.PresentationDuringIssuance(
                        selectCredentialsForPresentation = mockk(relaxed = true),
                        signVerifiablePresentation = mockk(relaxed = true)
                    )
                ),
                pkceSession
            )
        }

        assertEquals("access_denied", ex.issuerErrorCode)
        assertEquals("user cancelled the flow", ex.issuerErrorDescription)
        assertEquals(
            "Failed to authorize via interaction: authorization server error: access_denied - user cancelled the flow",
            ex.message
        )
    }

    @Test
    fun `should throw error on malformed JSON response`() = runTest {
        val responseBody = "{ invalid-json"

        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } returns NetworkResponse(responseBody, null)

        assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                listOf(
                    AuthorizationMethod.PresentationDuringIssuance(
                        selectCredentialsForPresentation = mockk(relaxed = true),
                        signVerifiablePresentation = mockk(relaxed = true)
                    )
                ),
                pkceSession
            )
        }
    }
    

    @Test
    fun `should throw error when OpenID4VP response parsing fails`() = runTest {
        val responseBody = """
            { "type": "openid4vp_presentation" }
        """.trimIndent()

        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } returns NetworkResponse(responseBody, null)

        val ex = assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                listOf(
                    AuthorizationMethod.PresentationDuringIssuance(
                        selectCredentialsForPresentation = mockk(relaxed = true),
                        signVerifiablePresentation = mockk(relaxed = true)
                    )
                ),
                pkceSession
            )
        }

        assert(ex.message.contains("Invalid presentation interaction response"))
    }

    @Test
    fun `should throw error when PresentationDuringIssuance method is missing`() = runTest {
        val responseBody = mockPresentationInteractionResponse

        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } returns NetworkResponse(responseBody, null)

        val ex = assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                authorizationMethods = emptyList(),
                pkceSession = pkceSession
            )
        }

        assert(ex.message.contains("No supported interaction types found"))
    }

    @Test
    fun `should wrap network failures as InteractiveAuthorizationException`() = runTest {
        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } throws RuntimeException("network down")

        val ex = assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                listOf(
                    AuthorizationMethod.PresentationDuringIssuance(
                        selectCredentialsForPresentation = mockk(relaxed = true),
                        signVerifiablePresentation = mockk(relaxed = true)
                    )
                ),

                pkceSession,

                )
        }

        assert(ex.message.contains("network down"))
    }

    @Test
    fun `should propagate InteractiveAuthorizationException directly`() = runTest {
        every {
            NetworkManager.sendRequest(any(), any(), any(), any())
        } throws InteractiveAuthorizationException("known error")

        val ex = assertFailsWith<InteractiveAuthorizationException> {
            handler.handle(
                endpoint,
                clientMetadata,
                credentialConfigId,
                listOf(
                    AuthorizationMethod.PresentationDuringIssuance(
                        selectCredentialsForPresentation = mockk(relaxed = true),
                        signVerifiablePresentation = mockk(relaxed = true)
                    )
                ),
                pkceSession
            )
        }

        assertEquals("Failed to authorize via interaction: known error", ex.message)
    }

@Test
fun `should include both OpenID4VP and IAE interaction types in initial IAR request`() = runTest {

    val responseBody = mockPresentationInteractionResponse

    mockkStatic(Base64::class)
    every { Base64.encodeToString(any<ByteArray>(), any()) } returns "b64"

    every {
        NetworkManager.sendRequest(
            url = endpoint,
            method = HttpMethod.POST,
            bodyParams = capture(mapSlot),
            headers = any()
        )
    } returns NetworkResponse(responseBody, null)

    val expected = mockk<AuthorizationResponse>()

    val presentationMethod =
        AuthorizationMethod.PresentationDuringIssuance(
            selectCredentialsForPresentation = mockk(relaxed = true),
            signVerifiablePresentation = mockk(relaxed = true)
        )

    mockkConstructor(PresentationDuringIssuanceAuthorizationMethodService::class)

    coEvery {
        anyConstructed<PresentationDuringIssuanceAuthorizationMethodService>()
            .authorizeUser(any())
    } returns expected

    handler.handle(
        endpoint = endpoint,
        clientMetadata = clientMetadata,
        credentialConfigurationId = credentialConfigId,
        authorizationMethods = listOf(presentationMethod),
        pkceSession = pkceSession
    )

   val interactionTypes = mapSlot.captured["interaction_types_supported"]

   assertEquals(
    "${InteractionType.OpenId4VpPresentation.value},${InteractionType.OpenId4VpPresentationIAE.value}",
    interactionTypes
)
}
}