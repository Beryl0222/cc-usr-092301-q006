// race_medical_dispatch 领域资料的基础结构。

export const EVENT_KINDS = Object.freeze(["EVENT_RISK_FILED", "RESOURCE_DECLARED", "PLAN_APPROVED", "INCIDENT_ESCALATED", "HANDOFF_COMPLETED"]);
export const REQUIRED_FIELDS = Object.freeze(["event_id", "kind", "occurred_at", "subject_id", "payload"]);

export function validateEvent(record) {
  const problems = REQUIRED_FIELDS.filter((name) => !(name in record));
  if (!EVENT_KINDS.includes(record.kind)) problems.push("kind");
  return problems;
}
