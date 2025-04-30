package io.mosip.vciclient.exception

class InvalidAccessTokenException(message: String?) :
    VCIClientException("VCI-003", "Access token is invalid - $message")