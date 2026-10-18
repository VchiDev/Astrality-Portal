
const APPS_SCRIPT_URL = process.env.ASTRALITY_APPS_SCRIPT_URL;
const API_SECRET = process.env.ASTRALITY_API_SECRET;

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      success: false,
      message: "Only POST requests are allowed."
    });
  }

  if (!APPS_SCRIPT_URL || !API_SECRET) {
    return res.status(500).json({
      success: false,
      message: "Server configuration is incomplete. Check the Vercel environment variables."
    });
  }

  let data = req.body;

  if (typeof data === "string") {
    try {
      data = JSON.parse(data);
    } catch {
      return res.status(400).json({
        success: false,
        message: "The request contains invalid JSON."
      });
    }
  }

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return res.status(400).json({
      success: false,
      message: "Invalid request data."
    });
  }

  if (typeof data.action !== "string" || !data.action.trim()) {
    return res.status(400).json({
      success: false,
      message: "A valid action is required."
    });
  }

  try {
    const response = await fetch(APPS_SCRIPT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        ...data,
        secret: API_SECRET
      }),
      redirect: "follow"
    });

    const responseText = await response.text();

    let result;

    try {
      result = JSON.parse(responseText);
    } catch {
      console.error(
        "Apps Script returned a non-JSON response. HTTP status:",
        response.status
      );

      return res.status(502).json({
        success: false,
        message: "The Astrality backend returned an unexpected response. Check your Apps Script deployment."
      });
    }

    if (!response.ok) {
      return res.status(502).json({
        success: false,
        message: "The Astrality backend could not complete the request."
      });
    }

    return res.status(200).json(result);
  } catch (error) {
    console.error("Astrality backend request failed:", error.message);

    return res.status(502).json({
      success: false,
      message: "Could not connect to the Astrality backend. Please try again."
    });
  }
};
