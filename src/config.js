import "dotenv/config";

export const config = {
  port: Number(process.env.PORT || 5000),

  frontendUrl:
    process.env.FRONTEND_URL || "http://localhost:5173",

  backendUrl:
    process.env.BACKEND_URL ||
    `http://localhost:${Number(process.env.PORT || 5000)}`,

  // LTI Tool Base URL
  ltiBaseUrl: process.env.LTI_BASE_URL || "",

  lti: {
    issuer: process.env.LTI_ISSUER || "",

    clientId: process.env.LTI_CLIENT_ID || "",

    authLoginUrl:
      process.env.LTI_AUTH_LOGIN_URL || "",

    tokenUrl:
      process.env.LTI_TOKEN_URL || "",

    platformJwksUrl:
      process.env.LTI_PLATFORM_JWKS_URL || "",

    deploymentId:
      process.env.LTI_DEPLOYMENT_ID || "",
  },

  sessionSecret:
    process.env.SESSION_SECRET ||
    "dev-only-change-this-secret-before-real-use",
};