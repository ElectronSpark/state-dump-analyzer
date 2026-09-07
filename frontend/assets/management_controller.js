import { requestControlPlane } from "./browser_transport.js";

export const MANAGEMENT_PREFIX = "/v1/control-plane";
export const MANAGEMENT_PAGE_SIZE = 50;

export function managementPath(...parts) {
  return MANAGEMENT_PREFIX + parts.map((part) => {
    if (typeof part !== "string" || !part || part.length > 512 || /[\u0000-\u001f\u007f]/.test(part)) {
      throw new TypeError("A non-empty, bounded scope identifier is required.");
    }
    return `/${encodeURIComponent(part)}`;
  }).join("");
}

export function managementVersion(value) {
  const raw = String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(raw) || BigInt(raw) > 9223372036854775807n
      || (typeof value === "number" && !Number.isSafeInteger(value))) {
    throw new TypeError("The server returned an invalid version; refresh before editing.");
  }
  return `"${raw}"`;
}

export function managementHealth(payload) {
  if (!payload || typeof payload !== "object") return "unavailable";
  return payload.status === "ok" || payload.status === "healthy" ? "healthy" : "attention";
}

export function createManagementClient({ fetchImpl = globalThis.fetch, uuid = () => crypto.randomUUID() } = {}) {
  let identity = null;
  let generation = 0;
  let pending = false;
  let uncertain = false;
  return {
    connect(tenantId, principalId) {
      for (const value of [tenantId, principalId]) {
        if (typeof value !== "string" || !value.trim() || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) {
          throw new TypeError("Enter valid tenant and principal IDs (up to 256 characters).");
        }
      }
      if (pending) throw new Error("Wait for the current write before changing identity.");
      identity = { tenantId: tenantId.trim(), principalId: principalId.trim() };
      generation += 1;
      uncertain = false;
    },
    disconnect() {
      if (pending) throw new Error("Wait for the current write before disconnecting.");
      identity = null; generation += 1; uncertain = false;
    },
    invalidate() { generation += 1; },
    get generation() { return generation; },
    get writing() { return pending; },
    get uncertain() { return uncertain; },
    async request(path, { method = "GET", body = null, version, mutation = method !== "GET", file = null, nodeHint, publicRead = false } = {}) {
      const url = new URL(path, "http://same-origin.invalid");
      if (url.origin !== "http://same-origin.invalid" || !path.startsWith("/") || path.includes("\\")
          || !(path === "/health" || path.startsWith(`${MANAGEMENT_PREFIX}/`)) || url.hash) {
        throw new TypeError("Management requests must remain on the same-origin control plane.");
      }
      if (publicRead && (method !== "GET" || !["/health", `${MANAGEMENT_PREFIX}/health`].includes(url.pathname))) {
        throw new TypeError("Only aggregate health may be requested anonymously.");
      }
      if (!publicRead && !identity) throw new Error("Connect an authorized identity first.");
      if (mutation && (pending || uncertain)) throw new Error(uncertain
        ? "A write has an uncertain outcome. Inspect server state before reconnecting; do not blindly repeat it."
        : "Another write is in progress.");
      if (nodeHint !== undefined && (!file || method !== "POST" || !mutation || publicRead
          || !/^\/v1\/control-plane\/projects\/[^/]+\/workspaces\/[^/]+\/imports$/.test(url.pathname)
          || typeof nodeHint !== "string" || !/^[!-~]{1,256}$/.test(nodeHint))) {
        throw new TypeError("A node hint is supported only for raw imports and must contain 1–256 printable ASCII characters without whitespace.");
      }
      const token = generation;
      const headers = { Accept: "application/json" };
      if (!publicRead) Object.assign(headers, { "X-Tenant-ID": identity.tenantId, "X-Principal-ID": identity.principalId });
      if (body !== null) headers["Content-Type"] = "application/json";
      if (file) headers["Content-Type"] = "application/octet-stream";
      if (nodeHint !== undefined) headers["X-Node-Hint"] = nodeHint;
      if (mutation) headers["Idempotency-Key"] = uuid();
      if (["PATCH", "DELETE", "PUT"].includes(method) && mutation) {
        if (version === undefined) throw new TypeError("Refresh this item to obtain its version before changing it.");
        headers["If-Match"] = managementVersion(version);
      }
      if (version !== undefined) headers["If-Match"] = managementVersion(version);
      if (mutation) pending = true;
      try {
        const result = await requestControlPlane(path, {
          method, body, headers, mutate: mutation, timeoutMs: file ? 120_000 : 30_000,
          fetchImpl: (target, options) => fetchImpl(target, { ...options, cache: "no-store", ...(file ? { body: file } : {}) }),
        });
        if (token !== generation) throw new Error("Scope changed; the stale response was discarded.");
        return result;
      } catch (error) {
        if (mutation && error.ambiguous) uncertain = true;
        throw error;
      } finally { if (mutation) pending = false; }
    },
  };
}
