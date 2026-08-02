// Pure timeline event presentation rules.
//
// The node workspace owns DOM/state orchestration.  This module owns the
// closed, plug-in-contract-driven classification used by both timeline marks
// and their tests, so changing a branch cannot silently alter the live UI.

export function normalizedEventOutcome(event) {
  if (event?.failure === true || event?.failed === true) return "failure";
  const value = event?.outcome;
  if (typeof value !== "string") return "unknown";
  const normalized = value.toLowerCase();
  return ["success", "failure", "unknown"].includes(normalized)
    ? normalized
    : "unknown";
}

export function eventFailed(event) {
  return event?.failure === true
    || event?.failed === true
    || normalizedEventOutcome(event) === "failure";
}

export function eventEffects(event) {
  return Array.isArray(event?.effects)
    ? event.effects.filter((effect) => effect && typeof effect === "object")
    : [];
}

export function eventChangesState(event) {
  if (event?.state_changed !== undefined) return Boolean(event.state_changed);
  const declared = eventEffects(event)
    .map((effect) => effect.state_changed)
    .filter((value) => value !== undefined && value !== null);
  return declared.length ? declared.some(Boolean) : null;
}

export function resourceEffectStatusClass(effect, event = null) {
  // These are transport aliases declared by the public plug-in contract.
  // Condition/status text is intentionally never interpreted here.
  let declared;
  if (effect && Object.prototype.hasOwnProperty.call(effect, "status_class")) {
    declared = effect.status_class;
  } else if (
    effect
    && Object.prototype.hasOwnProperty.call(effect, "condition_class")
  ) {
    declared = effect.condition_class;
  } else if (
    event
    && Object.prototype.hasOwnProperty.call(event, "status_class")
  ) {
    declared = event.status_class;
  } else if (
    event
    && Object.prototype.hasOwnProperty.call(event, "condition_class")
  ) {
    declared = event.condition_class;
  }
  return typeof declared === "string" && declared ? declared : "unknown";
}

export function eventMarkClass(mark) {
  if (mark?.failure === true) return "failure";
  const effectType = String(mark?.effectType || "unknown").toLowerCase();
  if (["created", "create"].includes(effectType)) return "create";
  if (["deleted", "delete"].includes(effectType)) return "delete";
  if (["modified", "modify", "unchanged"].includes(effectType)) return "modify";
  return "unknown";
}
