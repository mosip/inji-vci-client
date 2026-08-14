package io.mosip.vciclient.authorizationServer

import io.mosip.vciclient.common.JsonUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AuthorizationServerMetadataTest {

    @Test
    fun `should deserialize PAR requirement from authorization server metadata`() {
        val metadata = JsonUtils.deserialize(
            """{"issuer":"https://as.example","require_pushed_authorization_requests":true}""",
            AuthorizationServerMetadata::class.java
        )

        assertEquals(true, metadata?.requirePushedAuthorizationRequests)
    }

    @Test
    fun `should deserialize PAR requirement as false when advertised as false`() {
        val metadata = JsonUtils.deserialize(
            """{"issuer":"https://as.example","require_pushed_authorization_requests":false}""",
            AuthorizationServerMetadata::class.java
        )

        assertEquals(false, metadata?.requirePushedAuthorizationRequests)
    }

    @Test
    fun `should leave PAR requirement null when the authorization server omits it`() {
        val metadata = JsonUtils.deserialize(
            """{"issuer":"https://as.example","pushed_authorization_request_endpoint":"https://as.example/as/par"}""",
            AuthorizationServerMetadata::class.java
        )

        assertNull(metadata?.requirePushedAuthorizationRequests)
        assertEquals(
            "https://as.example/as/par",
            metadata?.pushedAuthorizationRequestEndpoint
        )
    }
}
