package io.mosip.vciclient.exception

import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.Test

class VCIClientExceptionTest {

    @Test
    fun `should retain root source error code from nested vci exceptions`() {
        val root = AuthorizationServerDiscoveryException("resolver failure")
        val wrapped = NetworkRequestFailedException(
            message = "token endpoint failed",
            serverErrorCode = "server_error",
            serverErrorDescription = "temporary issue",
            cause = root
        )

        assertEquals("VCI-001", wrapped.sourceErrorCode)
        assertEquals("VCI-006", wrapped.code)
        assertEquals("server_error", wrapped.serverErrorCode)
        assertEquals("temporary issue", wrapped.serverErrorDescription)
        assertEquals(
            "Network request failed, details - token endpoint failed",
            wrapped.message
        )
    }

    @Test
    fun `should construct invalid access token exception with server details`() {
        val exception = InvalidAccessTokenException(
            message = "expired",
            serverErrorCode = "invalid_token",
            serverErrorDescription = "token expired",
            cause = IllegalStateException("expired")
        )

        assertEquals("VCI-003", exception.code)
        assertEquals("invalid_token", exception.serverErrorCode)
        assertEquals("token expired", exception.serverErrorDescription)
        assertEquals("Access token is invalid - expired", exception.message)
    }

    @Test
    fun `should construct invalid data provided exception without server details`() {
        val exception = InvalidDataProvidedException("credential issuer missing")

        assertEquals("VCI-004", exception.code)
        assertNull(exception.serverErrorCode)
        assertNull(exception.serverErrorDescription)
        assertEquals(
            "Required details not provided credential issuer missing",
            exception.message
        )
    }

    @Test
    fun `should construct authorization server discovery exception with server details`() {
        val exception = AuthorizationServerDiscoveryException(
            message = "metadata endpoint unavailable",
            serverErrorCode = "temporarily_unavailable",
            serverErrorDescription = "retry later"
        )

        assertEquals("VCI-001", exception.code)
        assertEquals("temporarily_unavailable", exception.serverErrorCode)
        assertEquals("retry later", exception.serverErrorDescription)
        assertEquals(
            "Failed to discover authorization server : metadata endpoint unavailable",
            exception.message
        )
    }

    @Test
    fun `should construct network request failed exception without server details`() {
        val exception = NetworkRequestFailedException("connection reset")

        assertEquals("VCI-006", exception.code)
        assertNull(exception.serverErrorCode)
        assertNull(exception.serverErrorDescription)
        assertEquals(
            "Network request failed, details - connection reset",
            exception.message
        )
    }
}
