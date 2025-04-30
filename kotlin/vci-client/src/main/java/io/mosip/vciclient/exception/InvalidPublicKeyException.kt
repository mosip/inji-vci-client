package io.mosip.vciclient.exception

class InvalidPublicKeyException(message: String?) :
    VCIClientException("VCI-005", "Invalid public key passed $message")