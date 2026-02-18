package io.mosip.vciclient.exception

class InvalidDataProvidedException : VCIClientException {

    constructor(message: String?) : super(
        code = "VCI-004",
        message = "Required details not provided $message"
    )

    constructor(
        message: String?,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(
        code = "VCI-004",
        message = "Required details not provided $message",
        serverErrorCode = serverErrorCode,
        serverErrorDescription = serverErrorDescription,
        cause = cause
    )
}