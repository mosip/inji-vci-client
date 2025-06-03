package io.mosip.vciclient.exception

class NetworkRequestTimeoutException(message: String?) :
    VCIClientException("VCI-007", "Download failed due to request timeout - $message")