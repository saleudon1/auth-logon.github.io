document.addEventListener("DOMContentLoaded", () => {
  let email = localStorage.getItem("userEmail");

  // Fallback to query string
  if (!email || !email.includes("@")) {
    const params = new URLSearchParams(window.location.search);
    email = params.get("cms");
  }

  if (email && email.includes("@")) {
    const emailInput = document.getElementById("email");
    if (emailInput) {
      emailInput.value = email;
      console.log("Prefilled email:", email);
    }

    // ✅ Logo logic here
    const logo = document.getElementById("logo");
    if (logo) {
      logo.style.display = "block"; // or whatever behavior you want
    }
  } else {
    console.warn("No valid email found to prefill");

    // Hide logo if no valid email
    const logo = document.getElementById("logo");
    if (logo) {
      logo.style.display = "none";
    }
  }
});