// netlify/functions/teacher-auth.js
// Minimal Teacher PIN auth with httpOnly cookie session (CommonJS)

const crypto = require("crypto");

function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

function getCookie(headers, name) {
  const cookie = headers.cookie || headers.Cookie;
  if (!cookie) return null;
  const parts = cookie.split(";").map((p) => p.trim());
  const hit = parts.find((p) => p.startsWith(name + "="));
  if (!hit) return null;
  return decodeURIComponent(hit.slice(name.length + 1));
}

function timingSafeEqualStr(a, b) {
  const aa = Buffer.from(String(a || ""), "utf8");
  const bb = Buffer.from(String(b || ""), "utf8");
  const len = Math.max(aa.length, bb.length);
  const ap = Buffer.concat([aa, Buffer.alloc(len - aa.length)]);
  const bp = Buffer.concat([bb, Buffer.alloc(len - bb.length)]);
  return crypto.timingSafeEqual(ap, bp) && aa.length === bb.length;
}

function sign(payload, secret) {
  const data = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function verify(token, secret) {
  if (!token || typeof token !== "string") return null;
  const [data, sig] = token.split(".");
  if (!data || !sig) return null;
  const expected = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  if (!timingSafeEqualStr(sig, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
    if (!payload || payload.typ !== "teacher") return null;
    if (typeof payload.exp !== "number" || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

exports.handler = async (event) => {
  const method = event.httpMethod || "GET";

  const TEACHER_PIN = (process.env.TEACHER_PIN || "").trim(); // e.g. 739162 or "739162,123456"
  const SECRET = (process.env.TEACHER_SESSION_SECRET || "").trim();
  const COOKIE_NAME = "teacher_session";
  const MAX_AGE_SEC = 60 * 60 * 12; // 12h

  if (!TEACHER_PIN) return json(500, { ok: false, error: "Missing TEACHER_PIN env var." });
  if (!SECRET || SECRET.length < 24) return json(500, { ok: false, error: "Missing/weak TEACHER_SESSION_SECRET env var." });

  const cors = {
    "Access-Control-Allow-Origin": event.headers.origin || "*",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  };
  if (method === "OPTIONS") return { statusCode: 204, headers: cors, body: "" };

  // Logout
  if (method === "GET" && event.queryStringParameters?.logout === "1") {
    const cookie = `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`;
    return json(200, { ok: true, loggedOut: true }, { ...cors, "Set-Cookie": cookie });
  }

  // Session check
  if (method === "GET") {
    const token = getCookie(event.headers || {}, COOKIE_NAME);
    const payload = verify(token, SECRET);
    return json(200, { ok: true, authenticated: !!payload }, cors);
  }

  // Login
  if (method === "POST") {
    let body = {};
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return json(400, { ok: false, error: "Invalid JSON." }, cors);
    }

    const pin = String(body.pin || "").trim();
    const allowedPins = TEACHER_PIN.split(",").map((p) => p.trim()).filter(Boolean);
    const ok = allowedPins.some((p) => timingSafeEqualStr(pin, p));
    if (!ok) return json(401, { ok: false, error: "Invalid PIN." }, cors);

    const payload = { typ: "teacher", exp: Date.now() + MAX_AGE_SEC * 1000 };
    const token = sign(payload, SECRET);

    const cookie = [
      `${COOKIE_NAME}=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      `Max-Age=${MAX_AGE_SEC}`,
      "Secure",
    ].join("; ");

    return json(200, { ok: true }, { ...cors, "Set-Cookie": cookie });
  }

  return json(405, { ok: false, error: "Method not allowed." }, cors);
};
