package io.mosip.vciclient.authorizationCodeFlow.interactiveAuthorization.request

import junit.framework.TestCase.assertEquals
import org.junit.Test
import kotlin.test.assertTrue

class IARInitialRequestBodyTest {

    private fun body(dpopJkt: String = "thumb-print-value") = IARInitialRequestBody(
        clientId = "wallet-client",
        codeChallenge = "challenge",
        redirectUri = "wallet://callback",
        authorizationDetails = listOf(
            AuthorizationDetail(
                type = "openid_credential",
                credentialConfigurationId = "cred-id"
            )
        ),
        interactionTypesSupported = listOf("openid4vp_presentation"),
        dpopJkt = dpopJkt
    )

    @Test
    fun `toFormMap includes dpop_jkt`() {
        val map = body(dpopJkt = "thumb-print-value").toFormMap()

        assertEquals("thumb-print-value", map["dpop_jkt"])
    }

    @Test
    fun `toFormMap always includes the base authorization request fields`() {
        val map = body(dpopJkt = "x").toFormMap()

        assertEquals("code", map["response_type"])
        assertEquals("wallet-client", map["client_id"])
        assertEquals("challenge", map["code_challenge"])
        assertEquals("S256", map["code_challenge_method"])
        assertEquals("wallet://callback", map["redirect_uri"])
        assertTrue(map.containsKey("authorization_details"))
        assertEquals("openid4vp_presentation", map["interaction_types_supported"])
    }
}
