
/**
 * Astrality API — Vercel serverless function
 *
 * Required Vercel environment variables:
 *   ASTRALITY_APPS_SCRIPT_URL
 *   ASTRALITY_API_SECRET
 *
 * IMPORTANT:
 * Code.gs must verify the shared secret BEFORE processing any action.
 * Do not deploy this against an unprotected public Apps Script endpoint.
 */

const ALLOWED_ACTIONS = new Set(["signup", "login"]);

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      ok: false,
      error: "Method not allowed."
    });
  }

  const scriptUrl = process.env.ASTRALITY_APPS_SCRIPT_URL;
  const apiSecret = process.env.ASTRALITY_API_SECRET;

  if (!scriptUrl || !apiSecret) {
    return res.status(500).json({
      ok: false,
      error: "Astrality backend is not configured."
    });
  }

  // Only allow the expected Google Apps Script deployment URL.
  let parsedUrl;
  try {
    parsedUrl = new URL(scriptUrl);
  } catch {
    return res.status(500).json({
      ok: false,
      error: "Invalid backend configuration."
    });
  }

  if (
    parsedUrl.protocol !== "https:" ||
    parsedUrl.hostname !== "script.google.com" ||
    !parsedUrl.pathname.includes("/macros/s/") ||
    !parsedUrl.pathname.endsWith("/exec")
  ) {
    return res.status(500).json({
      ok: false,
      error: "Invalid backend configuration."
    });
  }

  const body = req.body;

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({
      ok: false,
      error: "Invalid request body."
    });
  }

  if (!ALLOWED_ACTIONS.has(body.action)) {
    return res.status(400).json({
      ok: false,
      error: "Unsupported action."
    });
  }

  // Basic field validation. The backend must validate again.
  if (body.action === "signup") {
    if (
      typeof body.name !== "string" ||
      typeof body.email !== "string" ||
      typeof body.password !== "string" ||
      body.name.length > 100 ||
      body.email.length > 254 ||
      body.password.length < 12 ||
      body.password.length > 128
    ) {
      return res.status(400).json({
        ok: false,
        error: "Please check your registration details."
      });
    }
  }

  if (body.action === "login") {
    if (
      typeof body.walletAddress !== "string" ||
      typeof body.password !== "string" ||
      body.walletAddress.length > 150 ||
      body.password.length < 1 ||
      body.password.length > 128
    ) {
      return res.status(400).json({
        ok: false,
        error: "Please check your login details."
      });
    }
  }

  try {
    const upstream = await fetch(scriptUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        ...body,
        serverSecret: apiSecret
      }),
      redirect: "follow",
      signal: AbortSignal.timeout(15000)
    });

    if (!upstream.ok) {
      return res.status(502).json({
        ok: false,
        error: "The Astrality backend is temporarily unavailable."
      });
    }

    const result = await upstream.json();

    if (!result || typeof result.ok !== "boolean") {
      return res.status(502).json({
        ok: false,
        error: "Unexpected response from the Astrality backend."
      });
    }

    // Never log passwords, secrets, or account data.
    return res.status(200).json(result);
  } catch {
    return res.status(502).json({
      ok: false,
      error: "Could not reach the Astrality backend."
    });
  }
}
