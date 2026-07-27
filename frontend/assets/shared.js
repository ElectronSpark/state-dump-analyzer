// Framework-free helpers shared by both core browser workspaces.
//
// Keep this module limited to generic presentation and transport behavior.
// Node, topology, route, and plug-in semantics belong in their respective
// entry points.

export const byId = (id) => document.getElementById(id);

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function safeClass(value) {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
}

export function titleCase(value) {
  return String(value ?? "unknown")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function toBigInt(value, fallback = 0n) {
  if (typeof value === "bigint") return value;
  if (value === null || value === undefined || value === "") return fallback;
  try {
    return BigInt(String(value).split(".")[0]);
  } catch (_error) {
    return fallback;
  }
}

export async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail || body.error?.message || message;
    } catch (_error) {
      // Keep the HTTP status when the body is not JSON.
    }
    throw new Error(message);
  }
  return response.json();
}
