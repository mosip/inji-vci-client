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
            issuerErrorCode = "server_error",
            issuerErrorDescription = "temporary issue",
            cause = root
        )

        assertEquals("VCI-001", wrapped.code)
        assertEquals("server_error", wrapped.issuerErrorCode)
        assertEquals("temporary issue", wrapped.issuerErrorDescription)
        assertEquals(
            "Network request failed, details - token endpoint failed",
            wrapped.message
        )
    }

    @Test
    fun `code resolves to deepest root code across multi-level chain`() {
        val root = InvalidDataProvidedException("missing field")
        val mid = AuthorizationServerDiscoveryException(
            message = "discovery failed",
            issuerErrorCode = null,
            issuerErrorDescription = null,
            cause = root
        )
        val outer = NetworkRequestFailedException(
            message = "token endpoint failed",
            cause = mid
        )

        assertEquals("VCI-004", outer.code)
    }

    @Test
    fun `should construct invalid access token exception with server details`() {
        val exception = InvalidAccessTokenException(
            message = "expired",
            issuerErrorCode = "invalid_token",
            issuerErrorDescription = "token expired",
            cause = IllegalStateException("expired")
        )

        assertEquals("VCI-003", exception.code)
        assertEquals("invalid_token", exception.issuerErrorCode)
        assertEquals("token expired", exception.issuerErrorDescription)
        assertEquals("Access token is invalid - expired", exception.message)
    }

    @Test
    fun `should construct invalid data provided exception without server details`() {
        val exception = InvalidDataProvidedException("credential issuer missing")

        assertEquals("VCI-004", exception.code)
        assertNull(exception.issuerErrorCode)
        assertNull(exception.issuerErrorDescription)
        assertEquals(
            "Required details not provided credential issuer missing",
            exception.message
        )
    }

    @Test
    fun `should construct authorization server discovery exception with server details`() {
        val exception = AuthorizationServerDiscoveryException(
            message = "metadata endpoint unavailable",
            issuerErrorCode = "temporarily_unavailable",
            issuerErrorDescription = "retry later"
        )

        assertEquals("VCI-001", exception.code)
        assertEquals("temporarily_unavailable", exception.issuerErrorCode)
        assertEquals("retry later", exception.issuerErrorDescription)
        assertEquals(
            "Failed to discover authorization server : metadata endpoint unavailable",
            exception.message
        )
    }

    @Test
    fun `should construct network request failed exception without server details`() {
        val exception = NetworkRequestFailedException("connection reset")

        assertEquals("VCI-006", exception.code)
        assertNull(exception.issuerErrorCode)
        assertNull(exception.issuerErrorDescription)
        assertEquals(
            "Network request failed, details - connection reset",
            exception.message
        )
    }

    @Test
    fun `should construct dpop exception without server details`() {
        val exception = DPoPException("DPoP session is not initialized for the current flow")

        assertEquals("VCI-013", exception.code)
        assertNull(exception.issuerErrorCode)
        assertNull(exception.issuerErrorDescription)
        assertEquals(
            "DPoP session is not initialized for the current flow",
            exception.message
        )
    }

    @Test
    fun `dpop exception retains root code when wrapping a vci exception`() {
        val exception = DPoPException(
            message = "Failed to sign DPoP proof: key unusable",
            cause = InvalidPublicKeyException("unsupported curve")
        )

        assertEquals("VCI-005", exception.code)
    }

    @Test
    fun `should construct illegal argument exception with a default message`() {
        val exception = IllegalArgumentException(null)

        assertEquals("VCI-012", exception.code)
        assertNull(exception.issuerErrorCode)
        assertNull(exception.issuerErrorDescription)
        assertEquals("An illegal argument was provided.", exception.message)
    }

    @Test
    fun `should construct illegal argument exception with server details`() {
        val exception = IllegalArgumentException(
            message = "authSession is required",
            issuerErrorCode = "invalid_request",
            issuerErrorDescription = "missing authSession"
        )

        assertEquals("VCI-012", exception.code)
        assertEquals("invalid_request", exception.issuerErrorCode)
        assertEquals("missing authSession", exception.issuerErrorDescription)
        assertEquals("authSession is required", exception.message)
    }
}
