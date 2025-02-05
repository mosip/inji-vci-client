# 3. credential-response-output

Date: 2024-10-24

## Status

Accepted

## Context
This document describes about the decision made regarding the output (Credential response) of the requestCredential method

In case of mso_mdoc format VC, issuer provides the credential in base 64 encoded CBOR data & in inji-vci-client library the credential response from the issuer is decoded and 
converted into JSON format (processed JSON) for the consumer app to perform rendering. If the consumer app, wants to perform any other processes which involves CBOR format conversion it becomes a tedious process to 
construct back the CBOR from the processed JSON.

## Decision

 - To support the consumer to interact with other services in the same format as OpenID4VCI specified credential response, the library will be sending the credential in unprocessed format.
 - The functionality of the library remains communicating with the issuing authority based on the issuer data provided by the wallet app and sending back the credential response to the wallet app


## Consequences

- Wallet will be taking the responsibility of processing or parsing the credential for rendering or any other purpose as per requirement 


**Note**
- Wallet -> Consumer app
