package io.mosip.vciclient.exception

class NetworkRequestTimeoutException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-007",
        message = "Network request timeout - $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-007",
        message = "Network request timeout - $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}