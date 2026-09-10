require("dotenv").config();
const express = require("express");
const path = require("path");
const {
  exchangeNpssoForAccessCode,
  exchangeAccessCodeForAuthTokens,
  exchangeRefreshTokenForAuthTokens,
  getProfileFromUserName,
} = require("psn-api");

const app = express();
const PORT = process.env.PORT || 3000;
const NPSSO = process.env.PSN_NPSSO;

app.use(express.static(path.join(__dirname, "public")));

/**
 * We keep the PSN access/refresh tokens in memory so we don't have to
 * re-authenticate with the NPSSO on every request. The NPSSO itself
 * never leaves this server and is never sent to the browser.
 */
let auth = null;
let accessTokenExpiresAt = 0;

async function authenticateWithNpsso() {
  if (!NPSSO) {
    throw new Error(
      "PSN_NPSSO is not set. Add it to your .env file — see README.md."
    );
  }
  const accessCode = await exchangeNpssoForAccessCode(NPSSO);
  auth = await exchangeAccessCodeForAuthTokens(accessCode);
  accessTokenExpiresAt = Date.now() + auth.expiresIn * 1000;
  return auth;
}

async function getAuth() {
  const now = Date.now();

  // Still valid? Reuse it.
  if (auth && now < accessTokenExpiresAt - 30_000) {
    return auth;
  }

  // Expired, but we have a refresh token — try that first, since it's
  // less likely than the NPSSO flow to be rate-limited.
  if (auth?.refreshToken) {
    try {
      auth = await exchangeRefreshTokenForAuthTokens(auth.refreshToken);
      accessTokenExpiresAt = now + auth.expiresIn * 1000;
      return auth;
    } catch (err) {
      console.warn("Refresh token failed, falling back to NPSSO:", err.message);
    }
  }

  return authenticateWithNpsso();
}

/**
 * Very small in-memory rate limiter. PSN can flag or rate-limit the
 * account behind the NPSSO if it gets hammered with lookups, so this
 * caps each visitor to 20 lookups per minute. It resets on restart and
 * isn't shared across multiple server instances — swap in a real
 * rate-limiting library/service if you deploy this behind a load
 * balancer or expect real traffic.
 */
const requestLog = new Map();
function isRateLimited(key) {
  const now = Date.now();
  const windowMs = 60_000;
  const max = 20;
  const recent = (requestLog.get(key) || []).filter((t) => now - t < windowMs);
  recent.push(now);
  requestLog.set(key, recent);
  return recent.length > max;
}

const ONLINE_ID_PATTERN = /^[a-zA-Z0-9_-]{3,16}$/;

app.get("/api/check/:onlineId", async (req, res) => {
  if (isRateLimited(req.ip)) {
    return res
      .status(429)
      .json({ error: "Too many lookups — wait a minute and try again." });
  }

  const onlineId = (req.params.onlineId || "").trim();

  if (!ONLINE_ID_PATTERN.test(onlineId)) {
    return res.status(400).json({
      error: "Enter a valid PSN online ID (3–16 letters, numbers, - or _).",
    });
  }

  try {
    const authorization = await getAuth();
    const { profile } = await getProfileFromUserName(authorization, onlineId);

    res.json({
      onlineId: profile.onlineId,
      accountId: profile.accountId,
      aboutMe: profile.aboutMe || "",
      avatarUrl: profile.avatarUrls?.[0]?.avatarUrl || null,
      isPlus: profile.plus === 1,
      isVerified: Boolean(profile.isOfficiallyVerified),
      onlineStatus: profile.primaryOnlineStatus || "unknown",
      trophy: {
        level: profile.trophySummary?.level ?? null,
        progress: profile.trophySummary?.progress ?? 0,
        platinum: profile.trophySummary?.earnedTrophies?.platinum ?? 0,
        gold: profile.trophySummary?.earnedTrophies?.gold ?? 0,
        silver: profile.trophySummary?.earnedTrophies?.silver ?? 0,
        bronze: profile.trophySummary?.earnedTrophies?.bronze ?? 0,
      },
    });
  } catch (err) {
    console.error(err);
    if (err.message?.includes("PSN_NPSSO")) {
      return res.status(500).json({ error: err.message });
    }
    res.status(404).json({
      error: `Couldn't find a public PSN profile for "${onlineId}".`,
    });
  }
});

app.listen(PORT, () => {
  console.log(`PSN ID checker running at http://localhost:${PORT}`);
});
