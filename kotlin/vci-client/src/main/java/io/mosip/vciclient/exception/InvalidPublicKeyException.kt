package io.mosip.vciclient.exception

class InvalidPublicKeyException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-005",
        message = "Invalid public key passed $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-005",
        message = "Invalid public key passed $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}
