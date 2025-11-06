// static/script.js
document.addEventListener("DOMContentLoaded", function () {
  const genBtn = document.getElementById("generateBtn");
  const suggestionDiv = document.getElementById("suggestion");
  const suggestedCode = document.getElementById("suggestedPW");
  const copyBtn = document.getElementById("copyBtn");
  const pwdInput = document.getElementById("passwordInput");
  const clearBtn = document.getElementById("clearBtn");
  const outputArea = document.getElementById("outputArea");

  if (genBtn) {
    genBtn.addEventListener("click", async function () {
      genBtn.disabled = true;
      genBtn.textContent = "Generating...";
      try {
        const res = await fetch("/generate");
        if (!res.ok) throw new Error("Network response not ok");
        const data = await res.json();
        const pw = data.password || "";
        suggestedCode.textContent = pw;
        if (pwdInput) pwdInput.value = pw;
        if (suggestionDiv) suggestionDiv.style.display = "block";
        if (outputArea) outputArea.scrollIntoView({behavior: "smooth", block: "start"});
      } catch (err) {
        console.error("Error fetching password:", err);
        alert("Could not generate password. Check the server or console.");
      } finally {
        genBtn.disabled = false;
        genBtn.textContent = "Suggest";
      }
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", function () {
      const text = suggestedCode ? suggestedCode.textContent : "";
      if (!text) return;
      navigator.clipboard.writeText(text).then(() => {
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy"), 1500);
      }).catch(() => {
        alert("Copy failed — please copy manually.");
      });
    });
  }

  if (clearBtn && outputArea) {
    clearBtn.addEventListener("click", function () {
      outputArea.innerHTML = "";
    });
  }
});
