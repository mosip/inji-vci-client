package io.mosip.vciclient.exception

class CredentialOfferFetchFailedException(message: String?) :
    VCIClientException("VCI-008", "Download failed due to fetching credentialOffer $message")