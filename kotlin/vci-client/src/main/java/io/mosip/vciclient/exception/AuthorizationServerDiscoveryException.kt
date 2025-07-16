package io.mosip.vciclient.exception

class AuthorizationServerDiscoveryException(
    message: String?,
) : VCIClientException(code = "VCI-001", "Failed to discover authorization server : $message")