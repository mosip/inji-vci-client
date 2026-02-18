package io.mosip.vciclient.exception

open class VCIClientException : Exception {

    val code: String
    val sourceErrorCode: String?
    val serverErrorCode: String?
    val serverErrorDescription: String?

    override val message: String
        get() = super.message ?: ""

    constructor(
        code: String,
        message: String,
        serverErrorCode: String? = null,
        serverErrorDescription: String? = null,
        cause: Throwable? = null
    ) : super(message, cause) {
        this.code = code
        this.sourceErrorCode = extractRootCode(cause)
        this.serverErrorCode = serverErrorCode
        this.serverErrorDescription = serverErrorDescription
    }

    companion object {
        private fun extractRootCode(cause: Throwable?): String? {
            var current = cause
            var lastCode: String? = null

            while (current != null) {
                if (current is VCIClientException) {
                    lastCode = current.code
                }
                current = current.cause
            }

            return lastCode
        }
    }
}
