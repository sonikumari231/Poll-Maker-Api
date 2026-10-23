import { createHash, generateKeyPairSync, createPublicKey, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, importPKCS8, SignJWT } from "jose";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const keyDirectory = path.join(__dirname, "../../keys");
const privateKeyPath = path.join(keyDirectory, "tool-private.pem");
const publicKeyPath = path.join(keyDirectory, "tool-public.pem");

function getKeyId(publicKey) {
  return createHash("sha256").update(publicKey).digest("base64url").slice(0, 22);
}

export async function ensureToolKeys() {
  await mkdir(keyDirectory, { recursive: true });
  try {
    await Promise.all([readFile(privateKeyPath), readFile(publicKeyPath)]);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const pair = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    await Promise.all([
      writeFile(privateKeyPath, pair.privateKey, { encoding: "utf8", mode: 0o600 }),
      writeFile(publicKeyPath, pair.publicKey, { encoding: "utf8", mode: 0o644 }),
    ]);
  }
}

export async function getToolJwks() {
  await ensureToolKeys();
  const publicKey = await readFile(publicKeyPath, "utf8");
  const jwk = await exportJWK(createPublicKey(publicKey));
  jwk.kid = getKeyId(publicKey);
  jwk.use = "sig";
  jwk.alg = "RS256";
  return { keys: [jwk] };
}

export async function signDeepLinkingResponse({ issuer, audience, claims }) {
  await ensureToolKeys();
  const [privateKey, publicKey] = await Promise.all([
    readFile(privateKeyPath, "utf8"),
    readFile(publicKeyPath, "utf8"),
  ]);
  const signingKey = await importPKCS8(privateKey, "RS256");

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: getKeyId(publicKey), typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("5m")
    .setJti(randomUUID())
    .sign(signingKey);
}
