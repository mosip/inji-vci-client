const DownloadFailedException = require("../src/exception/DownloadFailedException");
const NetworkRequestTimeoutException = require("../src/exception/NetworkRequestTimeoutException");
const { default: axios } = require("axios");
const VCIClient = require("../src/VCIClient.js");
const JWTProof = require("../src/proof/jwt/JWTProof.js");
const IssuerMetaData = require("../src/dto/issuerMetaData.js");

jest.mock("axios");

describe("VCI Client test", () => {
  const mockCredentialResponse = {
    format: "ldp_vc",
    credential: {
      issuanceDate: "2024-04-14T16:04:35.304Z",
      credentialSubject: {
        face: "data:image/jpeg;base64,/9j/goKCyuig",
        dateOfBirth: "2000/01/01",
        id: "did:jwk:eyJr80435=",
        UIN: "9012378996",
        email: "mockuser@gmail.com",
      },
      id: "https://domain.net/credentials/12345-87435",
      proof: {
        type: "RsaSignature2018",
        created: "2024-04-14T16:04:35Z",
        proofPurpose: "assertionMethod",
        verificationMethod: "https://domain.net/.well-known/public-key.json",
        jws: "eyJhbGciOiJSUzI11E_d-uifyj84U3XU8TA",
      },
      type: ["VerifiableCredential"],
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://domain.net/.well-known/context.json",
        {
          sec: "https://w3id.org/security#",
        },
      ],
      issuer: "https://domain.net/.well-known/issuer.json",
    },
  };
  const credentialEndpoint = "https://domain.net/credential";
  const credentialAudience = "https://domain.net";
  const downloadTimeoutInMillSeconds = 3000;
  const credentialType = ["VerifiableCredential"];
  const credentialFormat = "ldp_vc";
  const proof = new JWTProof("eyJhbdFQwRnFWZjIcQku5nL1E_d-uifyj84U3XU8TA");
  const accessToken = "eyJrahyw5Q_oeX7jXlHffwD2eBo3g";
  const issuerMetaData = new IssuerMetaData(
    credentialAudience,
    credentialEndpoint,
    downloadTimeoutInMillSeconds,
    credentialType,
    credentialFormat,
  );

  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.resetAllMocks();
  });

  const VCIClientTest = new VCIClient("AX12HG78XC78");

  it("should make api call to credential endpoint with the right params in case of ldpVc", async () => {
    axios.post.mockResolvedValue({ status: 200, data: mockCredentialResponse });

    const request = {
      requestBody: {
        format: "ldp_vc",
        credential_definition: {
          type: ["VerifiableCredential"],
          "@context": ["https://www.w3.org/2018/credentials/v1"],
        },
        proof: {
          proof_type: "jwt",
          jwt: "eyJhbdFQwRnFWZjIcQku5nL1E_d-uifyj84U3XU8TA",
        },
      },
      requestHeader: {
        Authorization: "Bearer eyJrahyw5Q_oeX7jXlHffwD2eBo3g",
        "Content-Type": "application/json",
      },
    };

    const resp = await VCIClientTest.requestCredential(issuerMetaData, proof, accessToken);

    expect(axios.post).toHaveBeenCalledWith(
      issuerMetaData.credentialEndpoint,
      JSON.stringify(request.requestBody),
      {
        timeout: issuerMetaData.downloadTimeoutInMillSeconds,
        headers: request.requestHeader,
      }
    );
    expect(resp).toEqual(mockCredentialResponse);
  });

  it("should return null when credential endpoint responded with empty body", async () => {
    axios.post.mockResolvedValue({ status: 200, data: "" });

    const resp = await VCIClientTest.requestCredential(issuerMetaData, proof, accessToken);

    expect(resp).toEqual(null);
  });

  it("should throw download failure exception when credential endpoint response is not 200", async () => {
    try {
      axios.post.mockImplementation(() => {
        const error = new DownloadFailedException("Request failed with status code 500");
        error.response = { status: 500 };
        return Promise.reject(error);
      });

      await VCIClientTest.requestCredential(issuerMetaData, proof, accessToken);
    } catch (error) {
      expect(error).toBeInstanceOf(DownloadFailedException);
      expect(error.message).toBe(
        "Request failed with status code 500"
      );
    }
  });

  it("should throw network request timeout failure exception when timeout is reached", async () => {
    axios.post.mockImplementation(
      () =>
        new Promise((_, reject) =>
          setTimeout(() => {
            const error = new NetworkRequestTimeoutException(
              "timeout exceeded"
            );
            error.code = "ECONNABORTED";
            reject(error);
          }, 4000)
        )
    );

    const requestPromise = VCIClientTest.requestCredential(issuerMetaData, proof, accessToken);

    jest.advanceTimersByTime(4000);

    await expect(requestPromise).rejects.toThrow(
      NetworkRequestTimeoutException
    );
    await expect(requestPromise).rejects.toThrow(
      "Download failure occurred due to Network request timeout, details - timeout exceeded"
    );
  }, 5000);
});