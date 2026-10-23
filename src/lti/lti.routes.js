import express from "express";

import crypto from "node:crypto";

import { createRemoteJWKSet, jwtVerify } from "jose";

import { config } from "../config.js";

import { getPollsByIds } from "../storage.js";
import { requireLtiSession } from "../auth/session.js";
import { getToolJwks, signDeepLinkingResponse } from "./keys.js";

const router = express.Router();

const LTI_VERSION = "1.3.0";

const RESOURCE_LINK_REQUEST = "LtiResourceLinkRequest";
const DEEP_LINKING_REQUEST = "LtiDeepLinkingRequest";
const DEEP_LINKING_RESPONSE = "LtiDeepLinkingResponse";

const LTI_CLAIMS = {
  version:
    "https://purl.imsglobal.org/spec/lti/claim/version",

  messageType:
    "https://purl.imsglobal.org/spec/lti/claim/message_type",

  deploymentId:
    "https://purl.imsglobal.org/spec/lti/claim/deployment_id",

  context:
    "https://purl.imsglobal.org/spec/lti/claim/context",

  resourceLink:
    "https://purl.imsglobal.org/spec/lti/claim/resource_link",

  roles:
    "https://purl.imsglobal.org/spec/lti/claim/roles",

  deepLinkingSettings:
    "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings",

  deepLinkingResponse:
    "https://purl.imsglobal.org/spec/lti-dl/claim/content_items",
};

function requireLtiConfig() {
  console.log("========== LTI CONFIG CHECK START ==========");

  const missing = [];

  if (!config.lti.issuer) {
    console.log("LTI_ISSUER is missing");
    missing.push("LTI_ISSUER");
  }

  if (!config.lti.clientId) {
    console.log("LTI_CLIENT_ID is missing");
    missing.push("LTI_CLIENT_ID");
  }

  if (!config.lti.authLoginUrl) {
    console.log("LTI_AUTH_LOGIN_URL is missing");
    missing.push("LTI_AUTH_LOGIN_URL");
  }

  if (!config.lti.platformJwksUrl) {
    console.log("LTI_PLATFORM_JWKS_URL is missing");
    missing.push("LTI_PLATFORM_JWKS_URL");
  }

  if (!config.ltiBaseUrl) {
    console.log("LTI_BASE_URL is missing");
    missing.push("LTI_BASE_URL");
  }

  if (missing.length > 0) {
    console.error("========== LTI CONFIG CHECK FAILED ==========");
    console.error("Missing configuration:", missing);

    throw new Error(
      `Missing LTI configuration: ${missing.join(", ")}`
    );
  }

  console.log("LTI configuration is valid");
  console.log("Issuer:", config.lti.issuer);
  console.log("Client ID:", config.lti.clientId);
  console.log("Auth Login URL:", config.lti.authLoginUrl);
  console.log("Platform JWKS URL:", config.lti.platformJwksUrl);
  console.log("LTI Base URL:", config.ltiBaseUrl);
  console.log(
    "Deployment ID:",
    config.lti.deploymentId
  );

  console.log("========== LTI CONFIG CHECK SUCCESS ==========");
}

function sameOriginHttpsOrLocalhost(urlString) {
  console.log("========== TARGET URL CHECK START ==========");
  console.log("Checking URL:", urlString);

  const url = new URL(urlString);

  const result =
    url.protocol === "https:" ||
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1";

  console.log("Protocol:", url.protocol);
  console.log("Hostname:", url.hostname);
  console.log("Target URL valid:", result);

  console.log("========== TARGET URL CHECK END ==========");

  return result;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]);
}

/**
 * Tool JWKS endpoint
 *
 * Moodle uses this URL to obtain the public key
 * used to verify tool-signed JWTs.
 */
router.get("/jwks", async (_req, res) => {
  console.log("========== LTI JWKS API START ==========");
  console.log("GET /lti/jwks called");

  try {
    console.log("Calling getToolJwks()");

    const jwks = await getToolJwks();

    console.log("getToolJwks() successful");
    console.log(
      "Number of JWKS keys:",
      jwks.keys?.length
    );

    console.log("========== LTI JWKS API SUCCESS ==========");

    return res.json(jwks);
  } catch (error) {
    console.error("========== LTI JWKS API FAILED ==========");
    console.error("JWKS error:", error);
    console.error("Error message:", error.message);
    console.error("Error stack:", error.stack);

    return res.status(500).json({
      error: "jwks_error",
      message: error.message,
    });
  }
});

/**
 * LTI 1.3 Login Initiation
 *
 * Moodle -> GET /lti/login
 */
router.all("/login", (req, res) => {
  console.log("========== LTI LOGIN START ==========");
  console.log("Method:", req.method);
  console.log("URL:", req.originalUrl);
  console.log("Session ID:", req.sessionID);

  try {
    console.log("STEP 1: Checking LTI configuration");

    requireLtiConfig();

    console.log(
      "STEP 1 SUCCESS: LTI configuration is valid"
    );

    const {
      iss,
      login_hint,
      target_link_uri,
      lti_message_hint,
    } = {
      ...req.query,
      ...req.body,
    };

    console.log(
      "STEP 2: Reading Moodle login parameters"
    );

    console.log("Issuer:", iss);
    console.log(
      "Login hint exists:",
      Boolean(login_hint)
    );
    console.log(
      "Target link URI:",
      target_link_uri
    );
    console.log(
      "LTI message hint exists:",
      Boolean(lti_message_hint)
    );

    if (!iss || !login_hint) {
      console.error(
        "LOGIN FAILED: iss or login_hint is missing"
      );

      console.error(
        "iss exists:",
        Boolean(iss)
      );

      console.error(
        "login_hint exists:",
        Boolean(login_hint)
      );

      return res.status(400).json({
        error: "invalid_request",
        message:
          "iss and login_hint are required by an LTI platform login initiation request.",
      });
    }

    console.log(
      "STEP 2 SUCCESS: Required parameters received"
    );

    console.log("STEP 3: Validating issuer");
    console.log("Received issuer:", String(iss));
    console.log(
      "Configured issuer:",
      config.lti.issuer
    );

    if (String(iss) !== config.lti.issuer) {
      console.error(
        "LOGIN FAILED: The issuer does not match"
      );

      return res.status(400).json({
        error: "invalid_issuer",
        message:
          "The supplied issuer does not match the configured LMS issuer.",
      });
    }

    console.log(
      "STEP 3 SUCCESS: Issuer validated successfully"
    );

    const target = String(
      target_link_uri || `${config.frontendUrl}/`
    );

    console.log("STEP 4: Target URL:", target);

    if (!sameOriginHttpsOrLocalhost(target)) {
      console.error(
        "LOGIN FAILED: Invalid target_link_uri"
      );

      return res.status(400).json({
        error: "invalid_target_link_uri",
        message:
          "Target link must use HTTPS or localhost during development.",
      });
    }

    console.log(
      "STEP 4 SUCCESS: Target URL validated"
    );

    console.log(
      "STEP 5: Generating state and nonce"
    );

    const state = crypto
      .randomBytes(32)
      .toString("hex");

    const nonce = crypto
      .randomBytes(32)
      .toString("hex");

    console.log(
      "STEP 5 SUCCESS: State and nonce generated"
    );

    console.log(
      "State length:",
      state.length
    );

    console.log(
      "Nonce length:",
      nonce.length
    );

    console.log(
      "STEP 6: Saving state, nonce and target in session"
    );

    req.session.ltiState = state;

    req.session.ltiNonce = nonce;

    req.session.targetLinkUri = target;

    console.log(
      "STEP 6 SUCCESS: LTI data saved in session"
    );

    console.log(
      "Session ID:",
      req.sessionID
    );

    console.log(
      "Session has state:",
      Boolean(req.session.ltiState)
    );

    console.log(
      "Session has nonce:",
      Boolean(req.session.ltiNonce)
    );

    console.log(
      "STEP 7: Creating Moodle authorization URL"
    );

    const url = new URL(
      config.lti.authLoginUrl
    );

    url.searchParams.set("scope", "openid");

    url.searchParams.set(
      "response_type",
      "id_token"
    );

    url.searchParams.set(
      "response_mode",
      "form_post"
    );

    url.searchParams.set(
      "client_id",
      config.lti.clientId
    );

    /**
     * IMPORTANT:
     * This is the backend callback URL.
     */
    const launchUrl =
      `${config.ltiBaseUrl.replace(
        /\/$/,
        ""
      )}/lti/launch`;

    console.log(
      "Launch URL:",
      launchUrl
    );

    url.searchParams.set(
      "redirect_uri",
      launchUrl
    );

    url.searchParams.set(
      "login_hint",
      String(login_hint)
    );

    url.searchParams.set(
      "state",
      state
    );

    url.searchParams.set(
      "nonce",
      nonce
    );

    url.searchParams.set(
      "prompt",
      "none"
    );

    if (lti_message_hint) {
      console.log(
        "Adding lti_message_hint to authorization URL"
      );

      url.searchParams.set(
        "lti_message_hint",
        String(lti_message_hint)
      );
    }

    console.log(
      "STEP 7 SUCCESS: Moodle authorization URL created"
    );

    console.log(
      "LTI login redirect:",
      url.toString()
    );

    console.log(
      "========== LTI LOGIN SUCCESS =========="
    );

    return res.redirect(url.toString());
  } catch (error) {
    console.error(
      "========== LTI LOGIN FAILED =========="
    );

    console.error(
      "LTI login failed:",
      error
    );

    console.error(
      "Error message:",
      error.message
    );

    console.error(
      "Error stack:",
      error.stack
    );

    return res.status(500).json({
      error: "lti_login_configuration_error",
      message: error.message,
    });
  }
});

/**
 * LTI 1.3 Launch
 *
 * Moodle -> POST /lti/launch
 *
 * IMPORTANT:
 * LTI launch is a POST containing:
 * - id_token
 * - state
 */
router.post("/launch", async (req, res) => {
  console.log("========== LTI LAUNCH START ==========");

  console.log("Method:", req.method);
  console.log("URL:", req.originalUrl);
  console.log("Session ID:", req.sessionID);

  try {
    console.log(
      "STEP 1: Checking LTI configuration"
    );

    requireLtiConfig();

    console.log(
      "STEP 1 SUCCESS: LTI configuration is valid"
    );

    const {
      id_token: idToken,
      state,
    } = req.body;

    console.log(
      "STEP 2: Reading launch parameters"
    );

    console.log(
      "id_token exists:",
      Boolean(idToken)
    );

    console.log(
      "id_token length:",
      idToken?.length
    );

    console.log(
      "state exists:",
      Boolean(state)
    );

    if (!idToken || !state) {
      console.error(
        "LAUNCH FAILED: id_token or state is missing"
      );

      return res.status(400).json({
        error: "invalid_request",
        message:
          "id_token and state are required.",
      });
    }

    console.log(
      "STEP 2 SUCCESS: id_token and state received"
    );

    /**
     * Validate state
     */
    console.log(
      "STEP 3: Validating LTI state"
    );

    console.log(
      "Session state exists:",
      Boolean(req.session.ltiState)
    );

    console.log(
      "State matches session:",
      state === req.session.ltiState
    );

    if (
      !req.session.ltiState ||
      state !== req.session.ltiState
    ) {
      console.error(
        "LAUNCH FAILED: LTI state validation failed"
      );

      return res.status(401).json({
        error: "invalid_state",
        message:
          "LTI state validation failed.",
      });
    }

    console.log(
      "STEP 3 SUCCESS: LTI state validated"
    );

    /**
     * Validate nonce exists
     */
    console.log(
      "STEP 4: Checking LTI nonce"
    );

    console.log(
      "Session nonce exists:",
      Boolean(req.session.ltiNonce)
    );

    if (!req.session.ltiNonce) {
      console.error(
        "LAUNCH FAILED: LTI nonce missing from session"
      );

      return res.status(401).json({
        error: "missing_nonce",
        message:
          "LTI nonce was not found in the session.",
      });
    }

    console.log(
      "STEP 4 SUCCESS: LTI nonce found"
    );

    /**
     * Moodle public JWKS
     */
    console.log(
      "STEP 5: Creating remote Moodle JWKS"
    );

    console.log(
      "Platform JWKS URL:",
      config.lti.platformJwksUrl
    );

    const JWKS = createRemoteJWKSet(
      new URL(config.lti.platformJwksUrl)
    );

    console.log(
      "STEP 5 SUCCESS: Remote JWKS created"
    );

    /**
     * Verify Moodle-signed ID token
     */
    console.log(
      "STEP 6: Verifying Moodle ID token"
    );

    console.log(
      "Expected issuer:",
      config.lti.issuer
    );

    console.log(
      "Expected audience:",
      config.lti.clientId
    );

    const { payload } = await jwtVerify(
      idToken,
      JWKS,
      {
        issuer: config.lti.issuer,

        audience: config.lti.clientId,

        algorithms: ["RS256"],

        nonce: req.session.ltiNonce,
      }
    );

    console.log(
      "STEP 6 SUCCESS: Moodle JWT verified"
    );

    console.log(
      "JWT issuer:",
      payload.iss
    );

    console.log(
      "JWT subject:",
      payload.sub
    );

    console.log(
      "JWT audience:",
      payload.aud
    );

    /**
     * Validate LTI version
     */
    console.log(
      "STEP 7: Validating LTI version"
    );

    console.log(
      "Received LTI version:",
      payload[LTI_CLAIMS.version]
    );

    console.log(
      "Expected LTI version:",
      LTI_VERSION
    );

    if (
      payload[LTI_CLAIMS.version] !==
      LTI_VERSION
    ) {
      console.error(
        "LAUNCH FAILED: Invalid LTI version"
      );

      throw new Error(
        "Not an LTI 1.3 message."
      );
    }

    console.log(
      "STEP 7 SUCCESS: LTI version validated"
    );

    /**
     * Validate message type
     */
    console.log(
      "STEP 8: Validating LTI message type"
    );

    const messageType =
      payload[LTI_CLAIMS.messageType];

    console.log(
      "Received message type:",
      messageType
    );

    console.log(
      "Expected message type:",
      `${RESOURCE_LINK_REQUEST} or ${DEEP_LINKING_REQUEST}`
    );

    if (
      messageType !== RESOURCE_LINK_REQUEST &&
      messageType !== DEEP_LINKING_REQUEST
    ) {
      console.error(
        "LAUNCH FAILED: Unsupported message type"
      );

      throw new Error(`Unsupported LTI message_type: ${messageType}`);
    }

    console.log(
      "STEP 8 SUCCESS: Message type validated"
    );

    /**
     * Validate deployment ID
     */
    console.log(
      "STEP 9: Validating deployment ID"
    );

    const deploymentId =
      payload[LTI_CLAIMS.deploymentId];

    console.log(
      "Received deployment ID:",
      deploymentId
    );

    console.log(
      "Configured deployment ID:",
      config.lti.deploymentId
    );

    if (
      config.lti.deploymentId &&
      deploymentId !== config.lti.deploymentId
    ) {
      console.error(
        "LAUNCH FAILED: Deployment ID mismatch"
      );

      throw new Error(
        "LTI deployment_id does not match configuration."
      );
    }

    console.log(
      "STEP 9 SUCCESS: Deployment ID validated"
    );

    /**
     * Context information
     */
    console.log(
      "STEP 10: Reading context information"
    );

    const context =
      payload[LTI_CLAIMS.context] || {};

    console.log(
      "Context:",
      context
    );

    /**
     * Resource link information
     */
    console.log(
      "STEP 11: Reading resource link information"
    );

    const resourceLink =
      payload[LTI_CLAIMS.resourceLink] || {};

    console.log(
      "Resource link:",
      resourceLink
    );

    /**
     * LMS roles
     */
    console.log(
      "STEP 12: Reading LMS roles"
    );

    const roles =
      payload[LTI_CLAIMS.roles] || [];

    console.log(
      "Roles:",
      roles
    );

    /**
     * Save LTI user information in session
     */
    console.log(
      "STEP 13: Saving LTI user information in session"
    );

    req.session.ltiUser = {
      userId: payload.sub || null,

      issuer: payload.iss || null,

      clientId: config.lti.clientId,

      deploymentId:
        deploymentId || null,

      contextId:
        context.id || null,

      contextTitle:
        context.title || null,

      resourceLinkId:
        resourceLink.id || null,

      resourceLinkTitle:
        resourceLink.title || null,

      roles,
    };

    if (messageType === DEEP_LINKING_REQUEST) {
      const settings = payload[LTI_CLAIMS.deepLinkingSettings];
      if (!settings || typeof settings.deep_link_return_url !== "string") {
        throw new Error("LTI Deep Linking settings or deep_link_return_url are missing.");
      }
      if (typeof deploymentId !== "string" || !deploymentId) {
        throw new Error("LTI Deep Linking deployment_id is missing.");
      }
      if (!sameOriginHttpsOrLocalhost(settings.deep_link_return_url)) {
        throw new Error("LTI Deep Linking deep_link_return_url must use HTTPS or localhost.");
      }
      if (!Array.isArray(settings.accept_types) || !settings.accept_types.includes("ltiResourceLink")) {
        throw new Error("LTI platform does not accept ltiResourceLink content items.");
      }

      req.session.deepLinkingSettings = {
        returnUrl: settings.deep_link_return_url,
        data: typeof settings.data === "string" ? settings.data : undefined,
        acceptMultiple: settings.accept_multiple === true,
        acceptTypes: settings.accept_types,
        acceptPresentationDocumentTargets: Array.isArray(settings.accept_presentation_document_targets)
          ? settings.accept_presentation_document_targets
          : [],
      };
    } else {
      req.session.deepLinkingSettings = null;
    }

    console.log(
      "STEP 13 SUCCESS: LTI user saved in session"
    );

    console.log(
      "Saved LTI user:",
      req.session.ltiUser
    );

    /**
     * Clear one-time OIDC values
     */
    console.log(
      "STEP 14: Clearing one-time state and nonce"
    );

    req.session.ltiState = null;

    req.session.ltiNonce = null;

    console.log(
      "STEP 14 SUCCESS: State and nonce cleared"
    );

    /**
     * Save session before redirecting
     */
    console.log(
      "STEP 15: Saving session"
    );

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error(
            "SESSION SAVE FAILED:",
            err
          );

          reject(err);
        } else {
          console.log(
            "Session saved successfully"
          );

          resolve();
        }
      });
    });

    console.log(
      "STEP 15 SUCCESS: Session saved"
    );

    /**
     * Redirect to React application
     */
    console.log(
      "STEP 16: Preparing frontend redirect"
    );

    const target = messageType === DEEP_LINKING_REQUEST
      ? new URL("/#/?deepLink=1", config.frontendUrl).toString()
      : req.session.targetLinkUri || `${config.frontendUrl}/`;

    req.session.targetLinkUri = null;

    console.log(
      "Target URL:",
      target
    );

    const targetUrl = new URL(target);

    targetUrl.searchParams.set("lti", "1");

    console.log(
      "LTI launch successful. Redirecting to:",
      targetUrl.toString()
    );

    console.log(
      "========== LTI LAUNCH SUCCESS =========="
    );

    return res.redirect(
      targetUrl.toString()
    );
  } catch (error) {
    console.error(
      "========== LTI LAUNCH FAILED =========="
    );

    console.error(
      "LTI launch failed:",
      error
    );

    console.error(
      "Error name:",
      error.name
    );

    console.error(
      "Error message:",
      error.message
    );

    console.error(
      "Error stack:",
      error.stack
    );

    return res.status(401).json({
      error: "invalid_lti_launch",
      message: error.message,
    });
  }
});

router.post("/deep-linking/respond", requireLtiSession, async (req, res, next) => {
  const settings = req.session.deepLinkingSettings;
  if (!settings) {
    return res.status(409).json({
      error: "deep_linking_not_active",
      message: "This session was not started by an LTI Deep Linking request.",
    });
  }

  const origin = req.get("origin");
  let validOrigin = false;
  try {
    validOrigin = Boolean(origin) &&
      new URL(origin).origin === new URL(config.frontendUrl).origin;
  } catch {
    validOrigin = false;
  }
  if (!validOrigin) {
    return res.status(403).json({
      error: "invalid_origin",
      message: "Deep Linking responses must be submitted from the configured frontend.",
    });
  }

  if (!settings.acceptTypes.includes("ltiResourceLink")) {
    return res.status(400).json({
      error: "unsupported_content_type",
      message: "The LMS does not accept LTI resource link content items.",
    });
  }

  const rawPollIds = req.body?.pollIds;
  const pollIds = typeof rawPollIds === "string"
    ? rawPollIds.split(",").filter(Boolean)
    : [];
  if (
    pollIds.length === 0 ||
    new Set(pollIds).size !== pollIds.length ||
    (!settings.acceptMultiple && pollIds.length > 1)
  ) {
    return res.status(400).json({
      error: "invalid_selection",
      message: "Select an allowed number of unique polls.",
    });
  }

  try {
    const selectedPolls = await getPollsByIds(pollIds);
    if (selectedPolls.some((poll) => !poll)) {
      return res.status(400).json({
        error: "poll_not_found",
        message: "One or more selected polls no longer exist.",
      });
    }

    const contentItems = selectedPolls.map((poll) => ({
      type: "ltiResourceLink",
      url: new URL(`/#/poll/${encodeURIComponent(poll.id)}`, config.frontendUrl).toString(),
      title: "Poll Maker",
    }));
    const responseClaims = {
      nonce: crypto.randomUUID(),
      [LTI_CLAIMS.version]: LTI_VERSION,
      [LTI_CLAIMS.messageType]: DEEP_LINKING_RESPONSE,
      [LTI_CLAIMS.deploymentId]: req.session.ltiUser.deploymentId,
      [LTI_CLAIMS.deepLinkingResponse]: contentItems,
    };
    if (settings.data !== undefined) {
      responseClaims.data = settings.data;
    }

    const jwt = await signDeepLinkingResponse({
      issuer: config.lti.clientId,
      audience: config.lti.issuer,
      claims: responseClaims,
    });

    req.session.deepLinkingSettings = null;
    await new Promise((resolve, reject) => {
      req.session.save((error) => error ? reject(error) : resolve());
    });

    res.set("Cache-Control", "no-store");
    return res.type("html").send(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Returning to LMS</title></head>
  <body>
    <p>Returning your selected poll${contentItems.length === 1 ? "" : "s"} to the LMS...</p>
    <form method="post" action="${escapeHtml(settings.returnUrl)}">
      <input type="hidden" name="JWT" value="${escapeHtml(jwt)}">
      <button type="submit">Continue</button>
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>`);
  } catch (error) {
    return next(error);
  }
});

/**
 * GET /lti/launch
 *
 * This endpoint should NOT perform an LTI launch.
 *
 * A valid LTI 1.3 launch must be POSTed by Moodle.
 *
 * This response prevents the confusing:
 * "Cannot GET /lti/launch"
 */
router.get("/launch", (_req, res) => {
  console.log("GET /lti/launch called");

  return res.status(405).json({
    error: "method_not_allowed",
    message: "LTI launch must be POSTed by Moodle.",
  });
});

/**
 * Debug configuration endpoint
 *
 * Does NOT expose secrets.
 */
router.get("/debug/config", (_req, res) => {
  console.log(
    "========== LTI DEBUG CONFIG =========="
  );

  console.log(
    "GET /lti/debug/config called"
  );

  console.log(
    "Issuer configured:",
    Boolean(config.lti.issuer)
  );

  console.log(
    "Client ID configured:",
    Boolean(config.lti.clientId)
  );

  console.log(
    "Auth Login URL configured:",
    Boolean(config.lti.authLoginUrl)
  );

  console.log(
    "Platform JWKS URL configured:",
    Boolean(config.lti.platformJwksUrl)
  );

  console.log(
    "LTI Base URL configured:",
    Boolean(config.ltiBaseUrl)
  );

  res.json({
    configured: Boolean(
      config.lti.issuer &&
        config.lti.clientId &&
        config.lti.authLoginUrl &&
        config.lti.platformJwksUrl &&
        config.ltiBaseUrl
    ),

    ltiBaseUrl:
      config.ltiBaseUrl || null,

    issuer:
      config.lti.issuer || null,

    clientId:
      config.lti.clientId || null,

    authLoginUrl:
      config.lti.authLoginUrl || null,

    platformJwksUrl:
      config.lti.platformJwksUrl || null,

    deploymentIdConfigured:
      Boolean(config.lti.deploymentId),
  });
});

export default router;