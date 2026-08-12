package io.mosip.vciclient.common

import java.net.URI

/**
 * Shared construction of `.well-known` metadata URLs, kept in one place so the
 * authorization-server discovery and issuer-metadata paths cannot drift apart in this
 * security-sensitive URL handling.
 */
object WellKnownUrl {

    /**
     * RFC 8414 section 3: insert the well-known [suffix] between the authority and the path of
     * [baseUrl]. e.g. `https://host/tenant` + `/.well-known/x` -> `https://host/.well-known/x/tenant`.
     * When [baseUrl] has no path this is equivalent to appending the suffix.
     */
    fun insertSuffix(baseUrl: String, suffix: String): String {
        val uri = URI(baseUrl)
        // Use rawPath so an escaped separator (e.g. /tenant%2Falpha) is not decoded into a
        // different path that would resolve to a different metadata endpoint.
        val path = uri.rawPath?.trimEnd('/').orEmpty()
        return "${uri.scheme}://${uri.authority}$suffix$path"
    }
}
