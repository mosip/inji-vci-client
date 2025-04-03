package io.mosip.vciclient.exception

class OfferFetchFailedException(message: String?) : Exception("Download failed due to $message")