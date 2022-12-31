const express = require("express");
const { auth, resolver, loaders } = require("@iden3/js-iden3-auth");
const getRawBody = require("raw-body");
const e = require("express");
require("dotenv").config();

const app = express();
const port = 8080;

app.use(express.static("static"));

app.get("/api/sign-in", (req, res) => {
  console.log("get Auth Request");
  GetAuthRequest(req, res);
});

app.post("/api/callback", (req, res) => {
  console.log("callback");
  Callback(req, res);
});

app.listen(port, () => {
  console.log("server running on port 8080");
});

// Create a map to store the auth requests and their session IDs
const requestMap = new Map();

// GetQR returns auth request
async function GetAuthRequest(req, res) {
  // Audience is verifier id
  const hostUrl = "http//localhost:8080";
  const sessionId = 1;
  const callbackURL = "/api/callback";

  const audience = "115WLAYLbY7AbcYoif27BPA56UYLhumBY4MTmyxXwr";

  const uri = `${hostUrl}${callbackURL}?sessionId=${sessionId}`;

  // Generate request for basic authentication
  const request = auth.createAuthorizationRequestWithMessage(
    "Check if Student or not",
    "Verifying that you are a student to avail benifits",
    audience,
    uri
  );

  //   request.id = "82ac48ac-49d1-448f-b274-19fe17f04a43";
  //   request.thid = "82ac48ac-49d1-448f-b274-19fe17f04a43";

  // Add request for a specific proof
  const proofRequest = {
    id: 1,
    circuit_id: "credentialAtomicQuerySig",
    rules: {
      query: {
        allowedIssuers: ["*"],
        schema: {
          type: "PresentStudentatUNI",
          url: "https://s3.eu-west-1.amazonaws.com/polygonid-schemas/f718ae8f-4ada-4120-b4f1-e4857cab10c8.json-ld",
        },
        req: {
          CurrentStudent: {
            $eq: 1, // bithDay field less then 2000/01/01
          },
        },
      },
    },
  };

  const scope = request.body.scope ?? [];
  request.body.scope = [...scope, proofRequest];

  // Store auth request in map associated with session ID
  requestMap.set(`${sessionId}`, request);

  return res.status(200).set("Content-Type", "application/json").send(request);
}

// Callback verifies the proof after sign-in callbacks
async function Callback(req, res) {
  // Get session ID from request
  const sessionId = req.query.sessionId;

  // get JWZ token params from the post request
  const raw = await getRawBody(req);
  const tokenStr = raw.toString().trim();

  // fetch authRequest from sessionID
  const authRequest = requestMap.get(`${sessionId}`);

  // Locate the directory that contains circuit's verification keys
  const verificationKeyloader = new loaders.FSKeyLoader("../keys");
  const sLoader = new loaders.UniversalSchemaLoader("ipfs.io");

  // Add Polygon Mumbai RPC node endpoint - needed to read on-chain state and identity state contract address
  const ethStateResolver = new resolver.EthStateResolver(
    "https://polygon-mumbai.g.alchemy.com/v2/bZFiL-IFAMe4QAh9Q30gDQ7m1vxEss4u",
    "0x46Fd04eEa588a3EA7e9F055dd691C688c4148ab3"
  );

  // EXECUTE VERIFICATION
  const verifier = new auth.Verifier(
    verificationKeyloader,
    sLoader,
    ethStateResolver
  );

  try {
    authResponse = await verifier.fullVerify(tokenStr, authRequest);
  } catch (error) {
    console.log(error);
    return res.status(500).send(error);
  }
  return res
    .status(200)
    .set("Content-Type", "application/json")
    .send("user with ID: " + authResponse.from + " Succesfully authenticated");
}
