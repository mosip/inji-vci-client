package io.mosip.vciclient.exception

class InvalidDataProvidedException(message: String?) :
    VCIClientException("VCI-004", "Required details not provided $message")