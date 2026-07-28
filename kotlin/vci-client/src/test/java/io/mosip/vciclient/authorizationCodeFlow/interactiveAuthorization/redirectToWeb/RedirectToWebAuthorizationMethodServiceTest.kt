package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.redirectToWeb

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mosip.vciclient.authorizationCodeFlow.implicitAuthorization.ImplicitAuthorizationRequestData
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.handler.InteractionType
import io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request.AuthorizationRequestData
import io.mosip.vciclient.authorizationServer.AuthorizationUrlBuilder
import io.mosip.vciclient.authorizationServer.PushedAuthorizationRequestService
import io.mosip.vciclient.authorizationServer.PushedAuthorizationResponse
import io.mosip.vciclient.constants.OpenWebPageCallback
import io.mosip.vciclient.exception.InteractiveAuthorizationException
import io.mosip.vciclient.pkce.PKCESessionManager
import io.mosip.vciclient.authorizationCodeFlow.clientMetadata.ClientMetadata
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertTrue

class RedirectToWebAuthorizationMethodServiceTest {

    private lateinit var openWebPage: OpenWebPageCallback

    @Before
    fun setup() {
        mockkObject(AuthorizationUrlBuilder)

        every {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any(),
                any()
            )
        } returns "https://auth.example.com/authorize"

        openWebPage = mockk()
    }


    @Test
    fun `type should return redirect_to_web`() {
        val service = RedirectToWebAuthorizationMethodService(openWebPage)
        assertEquals(InteractionType.RedirectToWeb.value, service.type())
    }


    @Test
    fun `should throw if requestData is not ImplicitAuthorizationRequestData`() = runTest {
        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val ex = assertThrows<InteractiveAuthorizationException> {
            service.authorizeUser(mockk<AuthorizationRequestData>())
        }
        print(ex)
        assertTrue {
            ex.message.contains("RedirectToWebAuthorizationHandler expects ImplicitAuthorizationRequestData but received AuthorizationRequestData")
        }
    }


    @Test
    fun `should return success response when redirect returns authorization_code`() = runTest {
        coEvery {
            openWebPage.invoke(any())
        } returns mapOf(
            "code" to "auth-code-123",
            "auth_session" to "session-xyz"
        )

        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val request = standardRequest()

        val response = service.authorizeUser(request)

        assertEquals("success", response.status)
        assertEquals("auth-code-123", response.authorizationCode)
        assertEquals("session-xyz", response.authSession)
        assertNull(response.error)
        assertNull(response.errorDescription)
    }


    @Test
    fun `should return error response when redirect returns error`() = runTest {
        coEvery {
            openWebPage.invoke(any())
        } returns mapOf(
            "error" to "access_denied",
            "error_description" to "User denied consent"
        )

        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val response = service.authorizeUser(standardRequest())

        assertEquals("error", response.status)
        assertEquals("access_denied", response.error)
        assertEquals("User denied consent", response.errorDescription)
        assertNull(response.authorizationCode)
    }


    @Test
    fun `should throw if authorization_code is missing in successful response`() = runTest {
        coEvery {
            openWebPage.invoke(any())
        } returns mapOf(
            "auth_session" to "session-xyz"
        )

        val service = RedirectToWebAuthorizationMethodService(openWebPage)

        val ex = assertThrows<InteractiveAuthorizationException> {
            service.authorizeUser(standardRequest())
        }

        assertEquals(
            "Failed to authorize via interaction: Missing authorization_code in successful redirect response",
            ex.message
        )
    }


    @Test
    fun `should push authorization request and use short URL when PAR endpoint present`() = runTest {
        every {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(any(), any(), any())
        } returns "https://auth.example.com/authorize?client_id=client-id&request_uri=urn:req:abc"

        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery {
            parService.pushAuthorizationRequest(
                parEndpoint = any(),
                clientId = any(),
                redirectUri = any(),
                codeChallenge = any(),
                state = any(),
                nonce = any(),
                scope = any()
            )
        } returns PushedAuthorizationResponse("urn:req:abc", 90)

        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(parRequest())

        assertEquals("success", response.status)
        assertEquals("auth-code-123", response.authorizationCode)

        coVerify(exactly = 1) {
            parService.pushAuthorizationRequest(
                parEndpoint = "https://as.example.com/as/par",
                clientId = "client-id",
                redirectUri = "app://callback",
                codeChallenge = "challenge",
                state = "state",
                nonce = "nonce",
                scope = "openid"
            )
        }
        io.mockk.verify(exactly = 1) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrlWithRequestUri(
                "https://auth.example.com", "client-id", "urn:req:abc"
            )
        }
    }

    @Test
    fun `should use long URL and not call PAR when PAR endpoint absent`() = runTest {
        val parService = mockk<PushedAuthorizationRequestService>()
        coEvery { openWebPage.invoke(any()) } returns mapOf("code" to "auth-code-123")

        val service = RedirectToWebAuthorizationMethodService(openWebPage, parService)
        val response = service.authorizeUser(standardRequest())

        assertEquals("success", response.status)
        assertEquals("auth-code-123", response.authorizationCode)

        coVerify(exactly = 0) {
            parService.pushAuthorizationRequest(
                parEndpoint = any(),
                clientId = any(),
                redirectUri = any(),
                codeChallenge = any(),
                state = any(),
                nonce = any(),
                scope = any()
            )
        }
        io.mockk.verify(exactly = 1) {
            AuthorizationUrlBuilder.buildAuthorizationRequestUrl(
                any(), any(), any(), any(), any(), any(), any(), any(), any()
            )
        }
    }

    private fun parRequest(): ImplicitAuthorizationRequestData {
        return ImplicitAuthorizationRequestData(
            authorizeUrl = "https://auth.example.com",
            clientMetadata = ClientMetadata(
                clientId = "client-id",
                redirectUri = "app://callback"
            ),
            pkceSession = PKCESessionManager.PKCESession(
                codeVerifier = "verifier",
                codeChallenge = "challenge",
                state = "state",
                nonce = "nonce"
            ),
            scope = "openid",
            pushedAuthorizationRequestEndpoint = "https://as.example.com/as/par"
        )
    }

    private fun standardRequest(): ImplicitAuthorizationRequestData {
        return ImplicitAuthorizationRequestData(
            authorizeUrl = "https://auth.example.com",
            clientMetadata = ClientMetadata(
                clientId = "client-id",
                redirectUri = "app://callback"
            ),
            pkceSession = PKCESessionManager.PKCESession(
                codeVerifier = "verifier",
                codeChallenge = "challenge",
                state = "state",
                nonce = "nonce"
            ),
            scope = "openid",
            dpopJkt = "dpop",
        )
    }
}
