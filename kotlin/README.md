# INJI VCI Client

## Features

- Request credential to Credential issuer and send the output Credential response

**_Note:_**
        _Consumer of this library will be taking the responsibility of processing or parsing the credential for rendering or any other purpose as per requirement_

## Installation

Snapshot builds are available [here](https://oss.sonatype.org/content/repositories/snapshots/io/mosip/inji-vci-client/).

```
implementation "io.mosip:inji-vci-client:0.3.0"
```

## Supported Credential formats
1. `ldp_Vc`
2. `mso_mdoc`

Refer [here](./vci-client/src/main/java/io/mosip/vciclient/constants/CredentialFormat.kt) for the format constant

## APIs

##### Request Credential

Request for credential from the providers (credential issuer), and receive the credential back.

```
val credentialResponse: CredentialResponse? = VCIClient().requestCredential(
                        issuerMetadata,
                        proof,
                        accessToken
                    )
```
###### Parameters

| Name           | Type            | Description                                                                | Sample                                                                                                       |
|----------------|-----------------|----------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| issuerMetaData | IssuerMetaData  | Data object of the issuer details                                          | `IssuerMetaData(credentialAudience, credentialEndpoint, downloadTimeout, credentialType, credentialFormat)`  |
| proofJwt       | Proof           | The proof used for making credential request. Supported proof types : JWT. | `JWTProof(jwtValue)`                                                                                         |                                                                                                         |
| accessToken    | String          | token issued by providers based on auth code                               | ""                                                                                                           |

###### Construction of issuerMetadata

1. Format: `ldp_vc`
```
val issuerMetadata = IssuerMetaData(
                        CREDENTIAL_AUDIENCE,
                        CREDENTIAL_ENDPOINT, 
                        DOWNLOAD_TIMEOUT, 
                        CREDENTIAL_TYPE, 
                        CredentialFormat.LDP_VC )
```
2. Format: `mso_mdoc`
```
val issuerMetadata = IssuerMetaData(
                        CREDENTIAL_AUDIENCE,
                        CREDENTIAL_ENDPOINT, 
                        DOWNLOAD_TIMEOUT, 
                        DOC_TYPE,
                        CLAIMS, 
                        CredentialFormat.MSO_MDOC )
```

###### Exceptions

1. DownloadFailedException is thrown when the credential issuer did not respond with credential response
2. NetworkRequestTimeoutException is thrown when the request is timedout

## More details

An example app is added under [/example](./example) folder which can be referenced for more details
