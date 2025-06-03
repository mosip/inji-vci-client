package io.mosip.vciclient.exception

class AuthServerDiscoveryException(
    message: String?,
) : VCIClientException(code = "VCI-001", "Failed to discover authorization server : $message")