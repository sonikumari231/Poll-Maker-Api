import express from "express";
import cors from "cors";
import session from "express-session";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./config.js";
import { ensureToolKeys } from "./lti/keys.js";
import ltiRoutes from "./lti/lti.routes.js";
import pollRoutes from "./poll/poll.routes.js";
import { requireLtiSession } from "./auth/session.js";
import authRoutes from "./auth/auth.routes.js";
import { initializeDatabase } from "./storage.js";

// const __dirname = path.dirname(fileURLToPath(import.meta.url));
// const frontendDist = path.join(__dirname, "../../frontend/dist");

await ensureToolKeys();
await initializeDatabase();

const app = express();

app.set("trust proxy", 1);

app.use(
  cors({
    origin: config.frontendUrl,
    credentials: true
  })
);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    name: "poll_lti_session",
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: "auto",
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 4
    }
  })
);

app.use((req, _res, next) => {
  if (req.session) {
    const isHttps = req.secure;
    req.session.cookie.secure = isHttps;
    req.session.cookie.sameSite = isHttps ? "none" : "lax";
  }
  next();
});

app.get("/api/status", (_req, res) => {
  res.json({
    name: "Poll Maker API",
    status: "ok",
    lti: "/lti/jwks"
  });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const user = req.session?.ltiUser || req.session?.user || null;
  res.json({
    authenticated: Boolean(user),
    authType: req.session?.ltiUser ? "lti" : req.session?.user ? "password" : null,
    user
  });
});

app.get("/api/lti/me", requireLtiSession, (req, res) => {
  res.json(req.session.ltiUser);
});

app.use("/lti", ltiRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/polls", pollRoutes);

// Serve the built React app
// app.use(express.static(frontendDist));

// Anything else (React Router routes) falls through to index.html
// app.get(/^\/(?!api|lti).*/, (_req, res) => {
//   res.sendFile(path.join(frontendDist, "index.html"));
// });

app.listen(config.port, () => {
  console.log(`Poll Maker backend running on http://localhost:${config.port}`);
  console.log(`LTI JWKS: http://localhost:${config.port}/lti/jwks`);
});