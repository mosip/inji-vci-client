package io.mosip.vciclient.credential.request.util

class ValidatorResult(var isValid: Boolean = true) {
    val invalidFields: MutableList<String> = ArrayList()
    fun addInvalidField(invalidField: String) {
        this.isValid = false
        this.invalidFields.add(invalidField)
    }
}