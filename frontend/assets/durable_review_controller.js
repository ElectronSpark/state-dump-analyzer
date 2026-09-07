import {
  ControlPlaneRequestError,
  listControlPlaneCollection,
  requestControlPlane,
} from "./browser_transport.js";

// Compatibility exports; generic transport is owned by browser_transport.js.
export { ControlPlaneRequestError, listControlPlaneCollection, requestControlPlane };

const PENDING_REVIEW_JOURNAL_SCHEMA_VERSION = 1;
const PENDING_REVIEW_PAYLOAD_IDENTITY_PATTERN = /^sha256:[0-9a-f]{64}$/;
const DEFAULT_PENDING_REVIEW_JOURNAL_MAXIMUM_ENTRIES = 256;
const DEFAULT_PENDING_REVIEW_JOURNAL_MAXIMUM_CHARACTERS = 1_048_576;
const DEFAULT_DURABLE_MUTATION_MAXIMUM_BYTES = 1_048_576;

function nonEmptyRequestToken(value, label, maximum = 256) {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > maximum
    || value !== value.trim()
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded non-empty token`);
  }
  return value;
}

/**
 * Build the only supported options shape for an idempotent durable creation.
 * Keeping this outside app.js makes mutation classification and header spelling
 * executable contract, rather than duplicated call-site convention.
 */
export function durableCreationRequestOptions({
  idempotencyKey,
  body,
  ...options
}) {
  return {
    ...options,
    method: "POST",
    mutate: true,
    headers: {
      ...(options.headers || {}),
      "Idempotency-Key": nonEmptyRequestToken(
        idempotencyKey,
        "idempotencyKey",
      ),
    },
    body,
  };
}

/** Build a version-guarded durable PATCH or DELETE request. */
export function durableConditionalRequestOptions({
  method,
  version,
  body = null,
  ...options
}) {
  const normalizedMethod = String(method || "").toUpperCase();
  if (normalizedMethod !== "PATCH" && normalizedMethod !== "DELETE") {
    throw new TypeError("conditional durable method must be PATCH or DELETE");
  }
  const normalizedVersion = nonEmptyRequestToken(String(version), "version");
  return {
    ...options,
    method: normalizedMethod,
    mutate: true,
    headers: {
      ...(options.headers || {}),
      "If-Match": `"${normalizedVersion}"`,
    },
    ...(body === null ? {} : { body }),
  };
}

/** Build an explicitly non-mutating POST used for bounded report queries. */
export function durableReadPostRequestOptions({ body, ...options }) {
  return {
    ...options,
    method: "POST",
    mutate: false,
    body,
  };
}

export class StaleDurableReviewConnectionError extends Error {
  constructor() {
    super("The durable review scope changed while the operation was in progress.");
    this.name = "StaleDurableReviewConnectionError";
  }
}

export class DurableReviewJournalError extends Error {
  constructor(message) {
    super(message);
    this.name = "DurableReviewJournalError";
  }
}

export class DurableReviewJournalCapacityError extends RangeError {
  constructor(message, capacity) {
    super(message);
    this.name = "DurableReviewJournalCapacityError";
    if (capacity !== "scope" && capacity !== "global") {
      throw new TypeError("journal capacity must be scope or global");
    }
    this.capacity = capacity;
  }
}

function durableMutationScope(token) {
  if (!token || typeof token !== "object") {
    throw new TypeError("durable review connection token is required");
  }
  return Object.freeze({
    tenantId: nonEmptyRequestToken(token.tenantId, "tenantId", 512),
    projectId: nonEmptyRequestToken(token.projectId, "projectId", 512),
    workspaceId: nonEmptyRequestToken(token.workspaceId, "workspaceId", 512),
    principalId: nonEmptyRequestToken(token.principalId, "principalId", 512),
    catalogRevisionId: nonEmptyRequestToken(
      token.catalogRevisionId,
      "catalogRevisionId",
      512,
    ),
  });
}

export function durableMutationScopeKey(token) {
  const scope = durableMutationScope(token);
  return [
    scope.tenantId,
    scope.projectId,
    scope.workspaceId,
    scope.principalId,
    scope.catalogRevisionId,
  ].join("\u001f");
}

function durableMutationServerScopeKey(token) {
  const scope = durableMutationScope(token);
  // Review object IDs and idempotency receipts are scoped by ReviewScope on
  // the server. Principal and catalog revision are UI connection dimensions,
  // not additional uniqueness namespaces for those durable identities.
  return [scope.tenantId, scope.projectId, scope.workspaceId].join("\u001f");
}

/** Compare durable scopes while deliberately ignoring connection generations. */
export function durableReviewScopesEqual(left, right) {
  if (!left || !right) return false;
  try {
    return durableMutationScopeKey(left) === durableMutationScopeKey(right);
  } catch (_error) {
    return false;
  }
}

function durableMutationPayloadDocument(payload, maximumBytes) {
  let encoded;
  try {
    encoded = JSON.stringify(payload);
  } catch (error) {
    throw new TypeError(`durable mutation payload must be JSON encodable: ${error.message}`);
  }
  if (typeof encoded !== "string") {
    throw new TypeError("durable mutation payload must be a JSON value");
  }
  const bytes = new TextEncoder().encode(encoded);
  if (bytes.byteLength > maximumBytes) {
    throw new RangeError(
      `durable mutation payload exceeds the ${maximumBytes}-byte identity limit`,
    );
  }
  return bytes;
}

function validatedPayloadIdentity(value) {
  if (
    typeof value !== "string"
    || !PENDING_REVIEW_PAYLOAD_IDENTITY_PATTERN.test(value)
  ) {
    throw new TypeError("payloadIdentity must be a lowercase SHA-256 identity");
  }
  return value;
}

async function defaultDigestPayload(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== "function") {
    throw new DurableReviewJournalError(
      "SHA-256 is unavailable; the durable mutation cannot be journaled safely.",
    );
  }
  return subtle.digest("SHA-256", bytes);
}

/** Return the exact wire-payload identity persisted for an unresolved write. */
export async function durableMutationPayloadIdentity(payload, {
  maximumBytes = DEFAULT_DURABLE_MUTATION_MAXIMUM_BYTES,
  digestImpl = defaultDigestPayload,
} = {}) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new RangeError("maximumBytes must be a positive safe integer");
  }
  if (typeof digestImpl !== "function") {
    throw new TypeError("digestImpl must be callable");
  }
  const bytes = durableMutationPayloadDocument(payload, maximumBytes);
  const rawDigest = await digestImpl(bytes);
  let digest;
  if (rawDigest instanceof ArrayBuffer) {
    digest = new Uint8Array(rawDigest);
  } else if (ArrayBuffer.isView(rawDigest)) {
    digest = new Uint8Array(
      rawDigest.buffer,
      rawDigest.byteOffset,
      rawDigest.byteLength,
    );
  } else {
    throw new DurableReviewJournalError("SHA-256 returned an invalid digest value.");
  }
  if (digest.byteLength !== 32) {
    throw new DurableReviewJournalError("SHA-256 returned an invalid digest length.");
  }
  return `sha256:${[...digest]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("")}`;
}

function pendingReviewMutationKey(scopeKey, kind, payloadIdentity) {
  return [scopeKey, kind, payloadIdentity].join("\u001e");
}

function pendingReviewMutationRecord({
  scope,
  kind,
  payloadIdentity,
  idempotencyKey,
  recordId,
}) {
  const normalizedScope = durableMutationScope(scope);
  const scopeKey = durableMutationScopeKey(normalizedScope);
  const normalizedKind = nonEmptyRequestToken(kind, "kind", 128);
  const normalizedPayloadIdentity = validatedPayloadIdentity(payloadIdentity);
  const normalizedIdempotencyKey = nonEmptyRequestToken(
    idempotencyKey,
    "idempotencyKey",
  );
  const normalizedRecordId = nonEmptyRequestToken(recordId, "recordId");
  if (normalizedIdempotencyKey === normalizedRecordId) {
    throw new RangeError("durable mutation identities must be distinct");
  }
  return Object.freeze({
    key: pendingReviewMutationKey(
      scopeKey,
      normalizedKind,
      normalizedPayloadIdentity,
    ),
    scope: normalizedScope,
    scopeKey,
    kind: normalizedKind,
    payloadIdentity: normalizedPayloadIdentity,
    idempotencyKey: normalizedIdempotencyKey,
    recordId: normalizedRecordId,
  });
}

/**
 * Reserve one operation identity in the unresolved durable-mutation journal.
 * A retry of the same wire payload reuses the original identity, while a
 * distinct payload receives a distinct key and record id.
 */
export function reservePendingReviewMutation(
  pendingMutations,
  token,
  kind,
  payloadIdentity,
  idPrefix,
  {
    maximumEntries = 128,
    maximumTotalEntries = DEFAULT_PENDING_REVIEW_JOURNAL_MAXIMUM_ENTRIES,
    createId = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
  } = {},
) {
  if (!(pendingMutations instanceof Map)) {
    throw new TypeError("pendingMutations must be a Map");
  }
  if (!Number.isSafeInteger(maximumEntries) || maximumEntries < 1) {
    throw new RangeError("maximumEntries must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maximumTotalEntries) || maximumTotalEntries < 1) {
    throw new RangeError("maximumTotalEntries must be a positive safe integer");
  }
  if (typeof createId !== "function") throw new TypeError("createId must be callable");
  const normalizedKind = nonEmptyRequestToken(kind, "kind", 128);
  const normalizedPrefix = nonEmptyRequestToken(idPrefix, "idPrefix", 128);
  const scope = durableMutationScope(token);
  const scopeKey = durableMutationScopeKey(token);
  const normalizedPayloadIdentity = validatedPayloadIdentity(payloadIdentity);
  const key = pendingReviewMutationKey(
    scopeKey,
    normalizedKind,
    normalizedPayloadIdentity,
  );
  const unresolved = pendingMutations.get(key);
  if (unresolved) return unresolved;
  const scopeEntries = [...pendingMutations.values()].filter(
    (item) => item?.scopeKey === scopeKey,
  );
  if (scopeEntries.length >= maximumEntries) {
    throw new DurableReviewJournalCapacityError(
      "Too many unresolved durable review writes in this scope; reconcile or discard them before creating another.",
      "scope",
    );
  }
  if (pendingMutations.size >= maximumTotalEntries) {
    throw new DurableReviewJournalCapacityError(
      "Too many unresolved durable review writes across this browser; reconcile or explicitly reset old scopes.",
      "global",
    );
  }
  const serverScopeKey = durableMutationServerScopeKey(scope);
  const usedIdentities = new Set();
  for (const item of pendingMutations.values()) {
    let itemServerScopeKey;
    try {
      itemServerScopeKey = durableMutationServerScopeKey(item?.scope);
    } catch (error) {
      throw new DurableReviewJournalError(
        `pending mutation journal entry is invalid: ${error.message}`,
      );
    }
    if (itemServerScopeKey !== serverScopeKey) continue;
    if (typeof item?.idempotencyKey === "string") {
      usedIdentities.add(item.idempotencyKey);
    }
    if (typeof item?.recordId === "string") usedIdentities.add(item.recordId);
  }
  const idempotencyKey = nonEmptyRequestToken(
    createId(normalizedKind),
    "generated idempotency key",
  );
  const recordId = nonEmptyRequestToken(
    createId(normalizedPrefix),
    "generated record id",
  );
  if (
    idempotencyKey === recordId
    || usedIdentities.has(idempotencyKey)
    || usedIdentities.has(recordId)
  ) {
    throw new RangeError(
      "durable mutation identity source must produce unique values",
    );
  }
  const pending = pendingReviewMutationRecord({
    scope,
    kind: normalizedKind,
    payloadIdentity: normalizedPayloadIdentity,
    idempotencyKey,
    recordId,
  });
  pendingMutations.set(key, pending);
  return pending;
}

function pendingReviewMutationDocument(pending) {
  const normalized = pendingReviewMutationRecord(pending);
  if (pending?.key !== normalized.key || pending?.scopeKey !== normalized.scopeKey) {
    throw new DurableReviewJournalError("pending mutation journal key is inconsistent");
  }
  return {
    scope: { ...normalized.scope },
    kind: normalized.kind,
    payload_identity: normalized.payloadIdentity,
    idempotency_key: normalized.idempotencyKey,
    record_id: normalized.recordId,
  };
}

function validatedJournalBounds(
  maximumEntries,
  maximumCharacters,
  maximumPerScopeEntries,
) {
  if (!Number.isSafeInteger(maximumEntries) || maximumEntries < 1) {
    throw new RangeError("maximumEntries must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maximumCharacters) || maximumCharacters < 1) {
    throw new RangeError("maximumCharacters must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maximumPerScopeEntries) || maximumPerScopeEntries < 1) {
    throw new RangeError("maximumPerScopeEntries must be a positive safe integer");
  }
}

/** Serialize only the bounded operation identity required for an exact retry. */
export function encodePendingReviewMutations(pendingMutations, {
  maximumEntries = DEFAULT_PENDING_REVIEW_JOURNAL_MAXIMUM_ENTRIES,
  maximumCharacters = DEFAULT_PENDING_REVIEW_JOURNAL_MAXIMUM_CHARACTERS,
  maximumPerScopeEntries = 128,
} = {}) {
  if (!(pendingMutations instanceof Map)) {
    throw new TypeError("pendingMutations must be a Map");
  }
  validatedJournalBounds(
    maximumEntries,
    maximumCharacters,
    maximumPerScopeEntries,
  );
  if (pendingMutations.size > maximumEntries) {
    throw new DurableReviewJournalError("pending mutation journal exceeds its entry limit");
  }
  const entries = [...pendingMutations.values()]
    .map(pendingReviewMutationDocument);
  const scopeCounts = new Map();
  const identitiesByServerScope = new Map();
  for (const entry of entries) {
    const scopeKey = durableMutationScopeKey(entry.scope);
    const count = (scopeCounts.get(scopeKey) || 0) + 1;
    if (count > maximumPerScopeEntries) {
      throw new DurableReviewJournalError(
        "pending mutation journal exceeds its per-scope entry limit",
      );
    }
    scopeCounts.set(scopeKey, count);
    const serverScopeKey = durableMutationServerScopeKey(entry.scope);
    if (!identitiesByServerScope.has(serverScopeKey)) {
      identitiesByServerScope.set(serverScopeKey, new Set());
    }
    const identities = identitiesByServerScope.get(serverScopeKey);
    if (
      identities.has(entry.idempotency_key)
      || identities.has(entry.record_id)
    ) {
      throw new DurableReviewJournalError(
        "pending mutation journal reuses a server-scoped operation identity",
      );
    }
    identities.add(entry.idempotency_key);
    identities.add(entry.record_id);
  }
  entries
    .sort((left, right) => {
      const leftKey = pendingReviewMutationKey(
        durableMutationScopeKey(left.scope),
        left.kind,
        left.payload_identity,
      );
      const rightKey = pendingReviewMutationKey(
        durableMutationScopeKey(right.scope),
        right.kind,
        right.payload_identity,
      );
      return leftKey.localeCompare(rightKey);
    });
  const encoded = JSON.stringify({
    schema_version: PENDING_REVIEW_JOURNAL_SCHEMA_VERSION,
    entries,
  });
  if (encoded.length > maximumCharacters) {
    throw new DurableReviewJournalError("pending mutation journal exceeds its storage limit");
  }
  return encoded;
}

export function decodePendingReviewMutations(encoded, {
  maximumEntries = DEFAULT_PENDING_REVIEW_JOURNAL_MAXIMUM_ENTRIES,
  maximumCharacters = DEFAULT_PENDING_REVIEW_JOURNAL_MAXIMUM_CHARACTERS,
  maximumPerScopeEntries = 128,
} = {}) {
  validatedJournalBounds(
    maximumEntries,
    maximumCharacters,
    maximumPerScopeEntries,
  );
  if (typeof encoded !== "string" || encoded.length > maximumCharacters) {
    throw new DurableReviewJournalError("pending mutation journal is not a bounded string");
  }
  let document;
  try {
    document = JSON.parse(encoded);
  } catch (_error) {
    throw new DurableReviewJournalError("pending mutation journal is not valid JSON");
  }
  if (
    !document
    || typeof document !== "object"
    || Array.isArray(document)
    || Object.keys(document).sort().join(",") !== "entries,schema_version"
    || document.schema_version !== PENDING_REVIEW_JOURNAL_SCHEMA_VERSION
    || !Array.isArray(document.entries)
    || document.entries.length > maximumEntries
  ) {
    throw new DurableReviewJournalError("pending mutation journal has an invalid envelope");
  }
  const pendingMutations = new Map();
  const identitiesByServerScope = new Map();
  const countsByScope = new Map();
  for (const entry of document.entries) {
    if (
      !entry
      || typeof entry !== "object"
      || Array.isArray(entry)
      || Object.keys(entry).sort().join(",")
        !== "idempotency_key,kind,payload_identity,record_id,scope"
    ) {
      throw new DurableReviewJournalError("pending mutation journal entry is invalid");
    }
    let pending;
    try {
      if (
        !entry.scope
        || typeof entry.scope !== "object"
        || Array.isArray(entry.scope)
        || Object.keys(entry.scope).sort().join(",")
          !== "catalogRevisionId,principalId,projectId,tenantId,workspaceId"
      ) {
        throw new TypeError("scope has an invalid shape");
      }
      pending = pendingReviewMutationRecord({
        scope: entry.scope,
        kind: entry.kind,
        payloadIdentity: entry.payload_identity,
        idempotencyKey: entry.idempotency_key,
        recordId: entry.record_id,
      });
    } catch (error) {
      throw new DurableReviewJournalError(
        `pending mutation journal entry is invalid: ${error.message}`,
      );
    }
    if (pendingMutations.has(pending.key)) {
      throw new DurableReviewJournalError("pending mutation journal contains a duplicate operation");
    }
    const serverScopeKey = durableMutationServerScopeKey(pending.scope);
    if (!identitiesByServerScope.has(serverScopeKey)) {
      identitiesByServerScope.set(serverScopeKey, new Set());
    }
    const scopeCount = (countsByScope.get(pending.scopeKey) || 0) + 1;
    if (scopeCount > maximumPerScopeEntries) {
      throw new DurableReviewJournalError(
        "pending mutation journal exceeds its per-scope entry limit",
      );
    }
    countsByScope.set(pending.scopeKey, scopeCount);
    const identities = identitiesByServerScope.get(serverScopeKey);
    if (
      identities.has(pending.idempotencyKey)
      || identities.has(pending.recordId)
    ) {
      throw new DurableReviewJournalError(
        "pending mutation journal reuses a server-scoped operation identity",
      );
    }
    identities.add(pending.idempotencyKey);
    identities.add(pending.recordId);
    pendingMutations.set(pending.key, pending);
  }
  return pendingMutations;
}

export function loadPendingReviewMutations(storage, key, options = {}) {
  if (!storage || typeof storage.getItem !== "function") {
    throw new DurableReviewJournalError("pending mutation journal storage is unavailable");
  }
  let encoded;
  try {
    encoded = storage.getItem(key);
  } catch (_error) {
    throw new DurableReviewJournalError("pending mutation journal storage is unavailable");
  }
  if (encoded === null || encoded === undefined || encoded === "") return new Map();
  return decodePendingReviewMutations(encoded, options);
}

export function savePendingReviewMutations(storage, key, pendingMutations, options = {}) {
  if (!storage || typeof storage.setItem !== "function") {
    throw new DurableReviewJournalError("pending mutation journal storage is unavailable");
  }
  const encoded = encodePendingReviewMutations(pendingMutations, options);
  try {
    storage.setItem(key, encoded);
  } catch (_error) {
    throw new DurableReviewJournalError("pending mutation journal could not be persisted");
  }
  return true;
}

export function resetPendingReviewMutationStorage(storage, key) {
  if (!storage || typeof storage.removeItem !== "function") {
    throw new DurableReviewJournalError("pending mutation journal storage is unavailable");
  }
  try {
    storage.removeItem(key);
  } catch (_error) {
    throw new DurableReviewJournalError("pending mutation journal could not be reset");
  }
  return true;
}

/** Remove the persisted journal before forgetting its in-memory identities. */
export function resetPendingReviewMutations(storage, key, pendingMutations) {
  if (!(pendingMutations instanceof Map)) {
    throw new TypeError("pendingMutations must be a Map");
  }
  resetPendingReviewMutationStorage(storage, key);
  const discarded = pendingMutations.size;
  pendingMutations.clear();
  return discarded;
}

export function discardPendingReviewMutationsForScope(
  pendingMutations,
  token,
) {
  if (!(pendingMutations instanceof Map)) {
    throw new TypeError("pendingMutations must be a Map");
  }
  const scopeKey = durableMutationScopeKey(token);
  let discarded = 0;
  for (const [key, pending] of pendingMutations) {
    if (pending?.scopeKey !== scopeKey) continue;
    pendingMutations.delete(key);
    discarded += 1;
  }
  return discarded;
}

export function completePendingReviewMutation(pendingMutations, pending) {
  if (!(pendingMutations instanceof Map)) {
    throw new TypeError("pendingMutations must be a Map");
  }
  if (!pending || typeof pending.key !== "string") return false;
  if (pendingMutations.get(pending.key) !== pending) return false;
  return pendingMutations.delete(pending.key);
}

/**
 * Execute one asynchronous operation only while its immutable connection token
 * remains current. Both checks are deliberate: the second closes the TOCTOU
 * window created by the await.
 */
export async function awaitCurrentDurableReview(operation, isCurrent) {
  if (typeof operation !== "function" || typeof isCurrent !== "function") {
    throw new TypeError("operation and isCurrent must be callable");
  }
  if (!isCurrent()) throw new StaleDurableReviewConnectionError();
  const value = await operation();
  if (!isCurrent()) throw new StaleDurableReviewConnectionError();
  return value;
}

/**
 * Bind one explicit review scope to the generic request transport.
 * Non-GET operations must declare whether they mutate, and durable mutations
 * must carry the operation identity/precondition required by their method.
 */
export async function requestDurableReview(path, {
  config,
  method = "GET",
  body = null,
  mutate = null,
  responseType = "json",
  headers = {},
  timeoutMs = 30_000,
  ...transport
} = {}) {
  if (!config || typeof config !== "object") {
    throw new TypeError("durable review config is required");
  }
  const identity = {};
  for (const field of ["tenantId", "projectId", "workspaceId", "principalId"]) {
    identity[field] = nonEmptyRequestToken(config[field], field, 512);
  }
  const normalizedMethod = String(method || "").toUpperCase();
  const nonGet = normalizedMethod !== "GET" && normalizedMethod !== "HEAD";
  if (nonGet && typeof mutate !== "boolean") {
    throw new TypeError("non-GET durable requests must declare mutate true or false");
  }
  const isMutation = mutate === true;
  if (!nonGet && isMutation) {
    throw new TypeError("GET and HEAD durable requests cannot be mutations");
  }
  if (nonGet && !isMutation && normalizedMethod !== "POST") {
    throw new TypeError("only report POST may be declared non-mutating");
  }
  const suppliedHeaders = { ...headers };
  if (isMutation && normalizedMethod === "POST") {
    nonEmptyRequestToken(suppliedHeaders["Idempotency-Key"], "Idempotency-Key");
  }
  if (
    isMutation
    && (normalizedMethod === "PATCH" || normalizedMethod === "DELETE")
  ) {
    nonEmptyRequestToken(suppliedHeaders["If-Match"], "If-Match");
  }
  return requestControlPlane(path, {
    ...transport,
    method: normalizedMethod,
    body,
    mutate: isMutation,
    responseType,
    headers: {
      ...suppliedHeaders,
      Accept: "application/json",
      "X-Tenant-ID": identity.tenantId,
      "X-Principal-ID": identity.principalId,
      ...(body === null ? {} : { "Content-Type": "application/json" }),
    },
    timeoutMs,
  });
}

function annotationCollectionPageDecision({
  payload,
  offset,
  requestedLimit,
  accumulatedCount,
  maximumCount,
}) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.items)) {
    throw new TypeError("annotation collection response must contain an items array");
  }
  if (payload.items.length > requestedLimit) {
    throw new RangeError("annotation collection page exceeds the requested limit");
  }
  const totalCount = accumulatedCount + payload.items.length;
  if (!Number.isSafeInteger(totalCount) || totalCount > maximumCount) {
    throw new RangeError("annotation collection exceeds the client safety cap");
  }
  if (payload.items.length < requestedLimit) {
    return {
      complete: true,
      capExceeded: false,
      nextOffset: null,
      totalCount,
    };
  }
  const nextOffset = offset + payload.items.length;
  if (!Number.isSafeInteger(nextOffset) || nextOffset <= offset) {
    throw new RangeError("annotation collection offset does not advance");
  }
  return {
    complete: false,
    capExceeded: totalCount >= maximumCount,
    nextOffset,
    totalCount,
  };
}

function annotationAuditWatermark(payload) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.items)) {
    throw new TypeError("annotation collection response must contain an items array");
  }
  const watermark = payload.audit_watermark;
  if (
    typeof watermark !== "string"
    || !/^(0|[1-9][0-9]*)$/.test(watermark)
    || BigInt(watermark) > 9_223_372_036_854_775_807n
  ) {
    throw new TypeError(
      "annotation collection response must contain a canonical audit_watermark string",
    );
  }
  return watermark;
}

/**
 * Read the complete bounded annotation index. Reaching the UI cap triggers a
 * one-record probe: an exact-cap collection succeeds, while any omitted record
 * fails visibly instead of silently replacing the confirmed marker set with a
 * partial result.
 */
export async function listAllDurableAnnotations(path, {
  request,
  origin,
  isCurrent,
  pageSize = 5_000,
  maximumRecords = 20_000,
} = {}) {
  if (typeof isCurrent !== "function") {
    throw new TypeError("isCurrent must be callable");
  }
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let expectedAuditWatermark = null;
    try {
      const items = await listControlPlaneCollection(path, {
        request,
        origin,
        pageDecision: annotationCollectionPageDecision,
        requestParameters: () => (
          expectedAuditWatermark === null
            ? {}
            : { expected_audit_watermark: expectedAuditWatermark }
        ),
        pageValidator: (payload) => {
          const watermark = annotationAuditWatermark(payload);
          if (expectedAuditWatermark === null) {
            expectedAuditWatermark = watermark;
          } else if (watermark !== expectedAuditWatermark) {
            throw new ControlPlaneRequestError(
              "Durable annotation index changed during pagination.",
              409,
            );
          }
        },
        pageSize,
        maximumRecords,
        assertCurrent: () => {
          if (!isCurrent()) throw new StaleDurableReviewConnectionError();
        },
        label: "Durable annotation index",
      });
      return {
        items,
        truncated: false,
        auditWatermark: expectedAuditWatermark,
      };
    } catch (error) {
      if (
        attempt === 0
        && error instanceof ControlPlaneRequestError
        && error.status === 409
      ) {
        continue;
      }
      throw error;
    }
  }
  throw new ControlPlaneRequestError(
    "Durable annotation index changed repeatedly during pagination.",
    409,
  );
}

export function loadDurableReviewConfig(storage, key) {
  try {
    const raw = JSON.parse(storage?.getItem?.(key) || "null");
    if (!raw || typeof raw !== "object") return null;
    const values = {
      tenantId: typeof raw.tenantId === "string" ? raw.tenantId.trim() : "",
      projectId: typeof raw.projectId === "string" ? raw.projectId.trim() : "",
      workspaceId: typeof raw.workspaceId === "string" ? raw.workspaceId.trim() : "",
      principalId: typeof raw.principalId === "string" ? raw.principalId.trim() : "",
    };
    return Object.values(values).every(Boolean) ? values : null;
  } catch (_error) {
    return null;
  }
}

export function saveDurableReviewConfig(storage, key, config) {
  try {
    storage?.setItem?.(key, JSON.stringify(config));
    return true;
  } catch (_error) {
    return false;
  }
}

export function beginReviewOperation(
  operations,
  name,
  conflicts = [name],
  createOwner = () => `${name}-${Date.now()}`,
) {
  if (!(operations instanceof Map)) throw new TypeError("operations must be a Map");
  if (conflicts.some((candidate) => operations.has(candidate))) return null;
  const owner = createOwner();
  operations.set(name, owner);
  return owner;
}

export function finishReviewOperation(operations, name, owner) {
  if (!(operations instanceof Map)) throw new TypeError("operations must be a Map");
  if (operations.get(name) !== owner) return false;
  operations.delete(name);
  return true;
}

export function durableReviewTokenMatches(token, current, { requireReady = true } = {}) {
  return Boolean(
    token
    && current?.config
    && token.sequence === current.sequence
    && token.tenantId === current.config.tenantId
    && token.projectId === current.config.projectId
    && token.workspaceId === current.config.workspaceId
    && token.principalId === current.config.principalId
    && token.catalogRevisionId === current.catalogRevisionId
    && (!requireReady || current.status === "ready"),
  );
}

export async function reconcileControlPlaneVersionConflict(
  error,
  { isCurrent, reload },
) {
  if (typeof isCurrent !== "function" || typeof reload !== "function") {
    throw new TypeError("isCurrent and reload must be callable");
  }
  if (
    !(error instanceof ControlPlaneRequestError)
    || error.status !== 409
    || !isCurrent()
  ) return false;
  try {
    await reload();
  } catch (_reloadError) {
    // Reconciliation is best effort; callers preserve the original conflict.
  }
  return true;
}

export function reconcilePendingReviewMutations(
  pendingMutations,
  scopeKey,
  { annotationIds = new Set(), correlationIds = new Set() } = {},
) {
  if (!(pendingMutations instanceof Map)) {
    throw new TypeError("pendingMutations must be a Map");
  }
  let reconciled = 0;
  for (const [key, pending] of pendingMutations) {
    if (!key.startsWith(`${scopeKey}\u001e`)) continue;
    const confirmed = (
      pending.kind === "timeline-marker" && annotationIds.has(pending.recordId)
    ) || (
      pending.kind === "manual-correlation" && correlationIds.has(pending.recordId)
    );
    if (!confirmed) continue;
    pendingMutations.delete(key);
    reconciled += 1;
  }
  return reconciled;
}

/**
 * Validate a complete annotation snapshot and build its marker projection
 * without touching the currently confirmed UI state. Callers can therefore
 * install the returned maps atomically after every row has proved usable.
 */
export function buildDurableAnnotationMarkerIndex(
  annotations,
  catalogRevisionId,
  entryIdForSubject,
) {
  if (!Array.isArray(annotations)) {
    throw new TypeError("durable annotation snapshot must be an array");
  }
  const revisionId = nonEmptyRequestToken(
    catalogRevisionId,
    "catalogRevisionId",
    1_024,
  );
  if (typeof entryIdForSubject !== "function") {
    throw new TypeError("entryIdForSubject must be callable");
  }
  const byId = new Map();
  const seenAnnotationIds = new Set();
  const annotationIdsByEntry = new Map();
  const markedEntryIds = new Set();
  const annotationKinds = new Set(["marker", "note", "tag"]);
  const subjectKinds = new Set([
    "event",
    "source_record",
    "resource",
    "relationship",
    "time_range",
  ]);
  for (const annotation of annotations) {
    if (!annotation || typeof annotation !== "object" || Array.isArray(annotation)) {
      throw new TypeError("durable annotation entry must be an object");
    }
    const annotationId = nonEmptyRequestToken(
      annotation.annotation_id,
      "annotation_id",
      1_024,
    );
    if (seenAnnotationIds.has(annotationId)) {
      throw new RangeError("durable annotation snapshot contains a duplicate annotation_id");
    }
    seenAnnotationIds.add(annotationId);
    if (!annotationKinds.has(annotation.kind)) {
      throw new TypeError("durable annotation entry has an unsupported kind");
    }
    if (!Number.isSafeInteger(annotation.version) || annotation.version < 1) {
      throw new TypeError("durable annotation entry must contain a positive version");
    }
    if (!Array.isArray(annotation.subjects) || annotation.subjects.length > 5_000) {
      throw new TypeError("durable annotation entry must contain a bounded subjects array");
    }
    for (const subject of annotation.subjects) {
      if (!subject || typeof subject !== "object" || Array.isArray(subject)) {
        throw new TypeError("durable annotation subject must be an object");
      }
      nonEmptyRequestToken(subject.revision_id, "subject revision_id", 1_024);
      if (!subjectKinds.has(subject.kind)) {
        throw new TypeError("durable annotation subject has an unsupported kind");
      }
      if (subject.kind !== "time_range") {
        nonEmptyRequestToken(subject.subject_id, "subject_id", 1_024);
      }
    }
    if (annotation.kind !== "marker") continue;
    byId.set(annotationId, annotation);
    for (const subject of annotation.subjects) {
      if (subject.revision_id !== revisionId) continue;
      const entryId = entryIdForSubject(subject);
      if (!entryId) continue;
      if (typeof entryId !== "string") {
        throw new TypeError("entryIdForSubject must return a string");
      }
      if (!annotationIdsByEntry.has(entryId)) {
        annotationIdsByEntry.set(entryId, new Set());
      }
      annotationIdsByEntry.get(entryId).add(annotationId);
      markedEntryIds.add(entryId);
    }
  }
  return { annotations: byId, annotationIdsByEntry, markedEntryIds };
}

/** Commit a freshly loaded confirmed snapshot only after the load fully succeeds. */
export async function loadThenCommitConfirmedState(load, commit) {
  if (typeof load !== "function" || typeof commit !== "function") {
    throw new TypeError("load and commit must be callable");
  }
  const confirmed = await load();
  commit(confirmed);
  return confirmed;
}
