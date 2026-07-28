package io.mosip.vciclient.dpop

internal data class WwwAuthenticateChallenge(
    val isDpop: Boolean,
    val isBearer: Boolean,
    val error: String?,
) {
    companion object {
        private val errorRegex = Regex("""error\s*=\s*"([^"]+)"""", RegexOption.IGNORE_CASE)
        private val dpopRegex = Regex("""(^|,|\s)DPoP(\s|$)""", RegexOption.IGNORE_CASE)
        private val bearerRegex = Regex("""(^|,|\s)Bearer(\s|$)""", RegexOption.IGNORE_CASE)
        private val dpopSchemeRegex = Regex("""DPoP\b.*""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))

        fun parse(headerValue: String?): WwwAuthenticateChallenge {
            if (headerValue.isNullOrBlank()) {
                return WwwAuthenticateChallenge(isDpop = false, isBearer = false, error = null)
            }
            val isDpop = dpopRegex.containsMatchIn(headerValue)
            val isBearer = bearerRegex.containsMatchIn(headerValue)
            // Attribute the error to the DPoP challenge segment so a Bearer error in the same
            // header (e.g. `Bearer error="invalid_token", DPoP error="use_dpop_nonce"`) is not
            // mistaken for the DPoP error.
            val errorSource = if (isDpop) {
                dpopSchemeRegex.find(headerValue)?.value ?: headerValue
            } else {
                headerValue
            }
            val error = errorRegex.find(errorSource)?.groupValues?.get(1)
            return WwwAuthenticateChallenge(isDpop = isDpop, isBearer = isBearer, error = error)
        }
    }
}
