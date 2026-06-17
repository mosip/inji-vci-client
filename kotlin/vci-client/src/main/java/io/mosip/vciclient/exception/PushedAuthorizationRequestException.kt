package io.mosip.vciclient.exception

class PushedAuthorizationRequestException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-PAR",
        message = "Pushed authorization request failed : $message"
    )

    constructor(
        message: String?,
        issuerErrorCode: String?,
        issuerErrorDescription: String?,
        cause: Throwable? = null
    ) : super(
        code = "VCI-PAR",
        message = "Pushed authorization request failed : $message",
        issuerErrorCode = issuerErrorCode,
        issuerErrorDescription = issuerErrorDescription,
        cause = cause
    )
}
