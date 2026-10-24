"use strict";

const form = document.getElementById("login-form");
const box = document.getElementById("login-error");

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = form.querySelector("button");
  btn.disabled = true;
  box.textContent = "";
  try {
    const res = await fetch(new URL("/api/login", location.origin), {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "f2b-web" },
      body: JSON.stringify({
        username: form.elements.namedItem("username").value.trim(),
        password: form.elements.namedItem("password").value,
      }),
    });
    if (res.ok) {
      location.replace("/");
      return;
    }
    let msg = `${res.status} ${res.statusText}`;
    try { msg = (await res.json()).error || msg; } catch (_) { /* sem JSON */ }
    box.innerHTML = "";
    const div = document.createElement("div");
    div.className = "alert";
    div.textContent = msg;
    box.appendChild(div);
    form.elements.namedItem("password").value = "";
    form.elements.namedItem("password").focus();
  } catch (e) {
    box.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
});
