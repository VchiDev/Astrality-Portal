
const crypto = require("crypto");
const { promisify } = require("util");

const pbkdf2 = promisify(crypto.pbkdf2);

const APPS_SCRIPT_URL = process.env.ASTRALITY_APPS_SCRIPT_URL;
const API_SECRET = process.env.ASTRALITY_API_SECRET;

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_KEY_LENGTH = 32;
const PBKDF2_DIGEST = "sha256";

function isPbkdf2Record(record) {
  return /^pbkdf2-sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}$/
    .test(String(record || ""));
}

async function makePasswordRecord(password) {
  const salt = crypto.randomBytes(16);

  const derivedKey = await pbkdf2(
    password,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_LENGTH,
    PBKDF2_DIGEST
  );

  return [
    "pbkdf2-sha256",
    PBKDF2_ITERATIONS,
    salt.toString("hex"),
    derivedKey.toString("hex")
  ].join("$");
}

function safeEqualStrings(a, b) {
  const first = Buffer.from(String(a), "utf8");
  const second = Buffer.from(String(b), "utf8");

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

async function verifyPassword(password, record) {
  if (typeof password !== "string") return false;

  record = String(record || "");

  // Current PBKDF2 format.
  if (isPbkdf2Record(record)) {
    const parts = record.split("$");
    const salt = Buffer.from(parts[2], "hex");
    const storedKey = Buffer.from(parts[3], "hex");

    const candidate = await pbkdf2(
      password,
      salt,
      PBKDF2_ITERATIONS,
      PBKDF2_KEY_LENGTH,
      PBKDF2_DIGEST
    );

    return storedKey.length === candidate.length &&
      crypto.timingSafeEqual(storedKey, candidate);
  }

  // Legacy Apps Script format: salt:Base64(SHA-256(salt + password)).
  const separator = record.indexOf(":");

  if (separator < 1) return false;

  const salt = record.substring(0, separator);
  const storedHash = record.substring(separator + 1);

  const candidate = crypto
    .createHash("sha256")
    .update(salt + password, "utf8")
    .digest("base64");

  return safeEqualStrings(storedHash, candidate);
}

async function callAppsScript(payload) {
  const response = await fetch(APPS_SCRIPT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      ...payload,
      // Always overwrite any supplied secret with the server secret.
      secret: API_SECRET
    }),
    redirect: "follow"
  });

  const responseText = await response.text();

  let result;

  try {
    result = JSON.parse(responseText);
  } catch {
    throw new Error("Astrality backend returned an unexpected response.");
  }

  if (!response.ok) {
    throw new Error("Astrality backend request failed.");
  }

  return result;
}

function sendFailure(res, message, status = 200) {
  return res.status(status).json({
    success: false,
    message,
    error: message
  });
}

async function getAuthRecord(walletAddress) {
  return callAppsScript({
    action: "getAuthRecord",
    walletAddress
  });
}

async function authenticateAndUpgrade(walletAddress, password) {
  if (
    typeof walletAddress !== "string" ||
    !walletAddress.trim() ||
    typeof password !== "string" ||
    !password ||
    password.length > 128
  ) {
    return false;
  }

  let result = await getAuthRecord(walletAddress);

  if (!result.success || !result.passwordHash) {
    return false;
  }

  if (!await verifyPassword(password, result.passwordHash)) {
    return false;
  }

  // Upgrade only after the legacy password has been verified.
  if (!isPbkdf2Record(result.passwordHash)) {
    const oldHash = result.passwordHash;
    const newHash = await makePasswordRecord(password);

    const migration = await callAppsScript({
      action: "migratePasswordHash",
      walletAddress,
      oldPasswordHash: oldHash,
      newPasswordHash: newHash
    });

    if (!migration.success) {
      // Another simultaneous login might have upgraded the hash first.
      // Read the current record and verify it before proceeding.
      result = await getAuthRecord(walletAddress);

      if (
        !result.success ||
        !result.passwordHash ||
        !isPbkdf2Record(result.passwordHash) ||
        !await verifyPassword(password, result.passwordHash)
      ) {
        return false;
      }
    }
  }

  return true;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return sendFailure(
      res,
      "Only POST requests are allowed.",
      405
    );
  }

  if (!APPS_SCRIPT_URL || !API_SECRET) {
    return sendFailure(
      res,
      "Server configuration is incomplete. Check the Vercel environment variables.",
      500
    );
  }

  let data = req.body;

  if (typeof data === "string") {
    try {
      data = JSON.parse(data);
    } catch {
      return sendFailure(
        res,
        "The request contains invalid JSON.",
        400
      );
    }
  }

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return sendFailure(res, "Invalid request data.", 400);
  }

  const action =
    typeof data.action === "string" ? data.action.trim() : "";

  if (!action) {
    return sendFailure(res, "A valid action is required.", 400);
  }

  // Internal authentication actions must never be public API actions.
  const publicActions = [
    "signup",
    "login",
    "balance",
    "transactions",
    "send",
    "deposit",
    "depositRequest"
  ];

  if (!publicActions.includes(action)) {
    return sendFailure(res, "Unknown API action.", 400);
  }

  try {
    /* ---------- Signup ---------- */

    if (action === "signup") {
      const displayName = String(data.displayName || "").trim();
      const email = String(data.email || "").trim().toLowerCase();
      const password = data.password;

      if (displayName.length < 2 || displayName.length > 40) {
        return sendFailure(
          res,
          "Account name must be 2–40 characters."
        );
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return sendFailure(res, "Enter a valid email address.");
      }

      if (
        typeof password !== "string" ||
        password.length < 8 ||
        password.length > 128
      ) {
        return sendFailure(
          res,
          "Password must be 8–128 characters."
        );
      }

      const passwordRecord = await makePasswordRecord(password);

      // The plaintext password is never forwarded to Apps Script.
      const result = await callAppsScript({
        action: "signup",
        displayName,
        email,
        passwordRecord
      });

      return res.status(200).json(result);
    }

    /* ---------- Login ---------- */

    if (action === "login") {
      const walletAddress = String(data.walletAddress || "").trim();
      const password = data.password;

      const valid = await authenticateAndUpgrade(
        walletAddress,
        password
      );

      if (!valid) {
        return sendFailure(
          res,
          "Invalid wallet address or password."
        );
      }

      // Do not forward the password or trust a client-supplied flag.
      const result = await callAppsScript({
        action: "login",
        walletAddress,
        verifiedByVercel: true
      });

      return res.status(200).json(result);
    }

    /* ---------- Other protected actions ---------- */

    const walletAddress = String(data.walletAddress || "").trim();
    const password = data.password;

    const valid = await authenticateAndUpgrade(
      walletAddress,
      password
    );

    if (!valid) {
      return sendFailure(
        res,
        "Authentication failed. Please sign in again."
      );
    }

    // Remove credentials and internal flags from the client's payload.
    const {
      password: _password,
      secret: _secret,
      apiSecret: _apiSecret,
      verifiedByVercel: _clientVerification,
      passwordRecord: _passwordRecord,
      ...forwardData
    } = data;

    const result = await callAppsScript({
      ...forwardData,
      action,
      walletAddress,
      verifiedByVercel: true
    });

    return res.status(200).json(result);

  } catch (error) {
    console.error("Astrality API error:", error.message);

    return sendFailure(
      res,
      "The request could not be completed. Please try again.",
      502
    );
  }
};
