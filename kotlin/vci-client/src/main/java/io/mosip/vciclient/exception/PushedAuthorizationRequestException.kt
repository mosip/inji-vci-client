package io.mosip.vciclient.exception

class PushedAuthorizationRequestException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-PAR",
        message = "Pushed authorization request failed : $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String?,
        serverErrorDescription: String?,
        cause: Throwable? = null
    ) : super(
        code = "VCI-PAR",
        message = "Pushed authorization request failed : $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}
