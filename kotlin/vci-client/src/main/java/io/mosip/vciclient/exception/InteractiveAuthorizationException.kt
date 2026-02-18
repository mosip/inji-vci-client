package io.mosip.vciclient.exception

class InteractiveAuthorizationException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-011",
        message = "Failed to authorize via interaction: $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-011",
        message = "Failed to authorize via interaction: $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}

