package io.mosip.vciclient.exception

class InvalidAccessTokenException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-003",
        message = "Access token is invalid - $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String?,
        serverErrorDescription: String?,
        cause: Throwable? = null
    ) : super(
        code = "VCI-003",
        message = "Access token is invalid - $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}
