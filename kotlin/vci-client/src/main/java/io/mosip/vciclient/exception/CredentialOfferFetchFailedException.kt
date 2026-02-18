package io.mosip.vciclient.exception

class CredentialOfferFetchFailedException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-008",
        message = "Failed to fetch credential offer: $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String?,
        serverErrorDescription: String?,
        cause: Throwable? = null
    ) : super(
        code = "VCI-008",
        message = "Failed to fetch credential offer: $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}
