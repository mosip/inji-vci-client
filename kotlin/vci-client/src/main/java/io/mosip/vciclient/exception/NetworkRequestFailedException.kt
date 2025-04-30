package io.mosip.vciclient.exception

class NetworkRequestFailedException(message: String?) : VCIClientException(
    "VCI-006",
    "Download failure occurred as Network request failed, details - $message"
)