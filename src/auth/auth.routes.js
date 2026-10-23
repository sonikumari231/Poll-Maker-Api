import { promisify } from "node:util";
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import express from "express";
import { createUser, getUserByEmail } from "../storage.js";

const router = express.Router();
const scrypt = promisify(scryptCallback);

router.post("/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("poll_lti_session", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    });
    return res.status(204).end();
  });
});

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

async function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const hash = await scrypt(password, salt, 64);
  return { salt, hash: hash.toString("hex") };
}

async function passwordMatches(password, user) {
  const candidate = await hashPassword(password, user.salt);
  return timingSafeEqual(Buffer.from(candidate.hash, "hex"), Buffer.from(user.passwordHash, "hex"));
}

router.post("/register", async (req, res, next) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "invalid_email", message: "Enter a valid email address." });
  }
  if (typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ error: "invalid_password", message: "Password must be at least 8 characters." });
  }

  try {
    const credentials = await hashPassword(password);
    const user = await createUser({
      id: randomUUID(),
      email,
      salt: credentials.salt,
      passwordHash: credentials.hash,
    });

    if (!user) {
      return res.status(409).json({ error: "email_in_use", message: "An account with that email already exists." });
    }

    return res.status(201).json({
      message: "Account created. Please sign in.",
      user: { id: user.id, email: user.email },
    });
  } catch (error) {
    return next(error);
  }
});

router.post("/login", async (req, res, next) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;

  if (!email || typeof password !== "string") {
    return res.status(400).json({ error: "invalid_credentials", message: "Email and password are required." });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user || !(await passwordMatches(password, user))) {
      return res.status(401).json({ error: "invalid_credentials", message: "Email or password is incorrect." });
    }

    req.session.user = { id: user.id, email: user.email };
    return req.session.save((error) => {
      if (error) return next(error);
      return res.json({ user: req.session.user });
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
