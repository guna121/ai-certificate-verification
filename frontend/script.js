/* =========================================================
   AI Certificate Verification — Shared JavaScript
   Handles: API calls, auth/token storage, navbar/sidebar logic
   ========================================================= */

// Change this if your backend runs on a different host/port.
const API_BASE = "http://127.0.0.1:8000";

// ---------------- Auth storage helpers ----------------

function saveAuth({ access_token, role, full_name }) {
  localStorage.setItem("cv_token", access_token);
  localStorage.setItem("cv_role", role);
  localStorage.setItem("cv_name", full_name);
}

function getToken() {
  return localStorage.getItem("cv_token");
}

function getRole() {
  return localStorage.getItem("cv_role");
}

function getName() {
  return localStorage.getItem("cv_name") || "";
}

function clearAuth() {
  localStorage.removeItem("cv_token");
  localStorage.removeItem("cv_role");
  localStorage.removeItem("cv_name");
}

function logout() {
  clearAuth();
  window.location.href = "login.html";
}

// Redirect to login if not authenticated. Call at the top of protected pages.
function requireAuth() {
  if (!getToken()) {
    window.location.href = "login.html";
  }
}

// ---------------- API helper ----------------

async function apiFetch(path, options = {}) {
  const headers = options.headers || {};
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;

  // Don't set Content-Type for FormData — the browser sets the boundary itself.
  if (!(options.body instanceof FormData) && options.body) {
    headers["Content-Type"] = "application/json";
  }

  let response;
  try {
    response = await fetch(API_BASE + path, { ...options, headers });
  } catch (err) {
    throw new Error("Could not reach the server. Is the backend running on " + API_BASE + "?");
  }

  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    /* no JSON body */
  }

  if (!response.ok) {
    const message = (data && data.detail) || `Request failed (${response.status})`;
    if (response.status === 401) {
      clearAuth();
    }
    throw new Error(typeof message === "string" ? message : JSON.stringify(message));
  }

  return data;
}

// ---------------- Small UI helpers ----------------

function showAlert(elId, message, type = "error") {
  const el = document.getElementById(elId);
  if (!el) return;
  el.textContent = message;
  el.className = `alert alert-${type} show`;
}

function hideAlert(elId) {
  const el = document.getElementById(elId);
  if (el) el.classList.remove("show");
}

function initials(name) {
  if (!name) return "?";
  return name
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((p) => p[0].toUpperCase())
    .join("");
}

function formatDate(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString.replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return isoString;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

const RESULT_META = {
  verified: { emoji: "✅", label: "Verified", desc: "This certificate matches our verified records.", color: "#16a34a" },
  needs_review: { emoji: "⚠️", label: "Needs Review", desc: "Some details couldn't be fully confirmed — manual review recommended.", color: "#d97706" },
  suspicious: { emoji: "❌", label: "Suspicious", desc: "This certificate shows signs of being fake or altered.", color: "#dc2626" },
  revoked: { emoji: "🚫", label: "Revoked", desc: "This certificate was cancelled by the issuing institution.", color: "#6b21a8" },
};

// ---------------- Sidebar (dashboard shell) ----------------

function initSidebar(activeKey) {
  document.querySelectorAll(".sidebar-link").forEach((link) => {
    if (link.dataset.key === activeKey) link.classList.add("active");
  });

  const nameEl = document.getElementById("sidebar-user-name");
  const roleEl = document.getElementById("sidebar-user-role");
  const avatarEl = document.getElementById("sidebar-avatar");
  if (nameEl) nameEl.textContent = getName() || "User";
  if (roleEl) roleEl.textContent = getRole() || "";
  if (avatarEl) avatarEl.textContent = initials(getName());

  const toggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
  }

  // Hide role-restricted sidebar links (e.g., "Admin" link for non-admins).
  const role = getRole();
  document.querySelectorAll("[data-roles]").forEach((el) => {
    const allowed = el.dataset.roles.split(",");
    if (!allowed.includes(role)) el.style.display = "none";
  });

  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) logoutBtn.addEventListener("click", logout);
}
