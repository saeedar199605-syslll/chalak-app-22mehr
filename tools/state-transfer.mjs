// tools/state-transfer.ts
import fs from "node:fs";

// cloudflare/syncState.ts
var INTERNAL_STATE_KEYS = /* @__PURE__ */ new Set(["__operation_receipts"]);
var CLOUD_SYNC_KEYS = /* @__PURE__ */ new Set([
  "pe_violations",
  "pe_violation_policy",
  "pe_violation_operations",
  "pe_job_family_assignments",
  "pe_employees",
  "pe_criteria",
  "pe_profiles",
  "pe_evaluations",
  "pe_notifications",
  "pe_granular_permissions",
  "pe_archived_evaluations",
  "pe_active_period",
  "pe_workshop_targets",
  "pe_lattice_okrs",
  "pe_lattice_one_on_ones",
  "pe_lattice_kudos",
  "pe_lattice_pulse",
  "pe_locked_users",
  "pe_role_permissions",
  "pe_user_custom_permissions",
  "pe_manual_access_policy",
  "pe_reward_config",
  "pe_reward_batch_history",
  "pe_tickets",
  "pe_route_rules",
  "pe_workflow_sla",
  "pe_kickidler_live",
  "pe_kickidler_records",
  "pe_kickidler_violations",
  "pe_supervisor_calendar_events",
  "pe_auto_archive_settings",
  "pe_system_logs",
  "pe_audit_logs",
  "pe_route_rules",
  "pe_delegations"
]);
function isCloudSyncKey(key) {
  return CLOUD_SYNC_KEYS.has(key);
}
function sanitizeCloudState(input, includeInternal = false) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (isCloudSyncKey(key) || includeInternal && INTERNAL_STATE_KEYS.has(key)) output[key] = value;
  }
  return output;
}

// src/utils/personnelSearch.ts
var DIGIT_MAP = {
  "\u06F0": "0",
  "\u06F1": "1",
  "\u06F2": "2",
  "\u06F3": "3",
  "\u06F4": "4",
  "\u06F5": "5",
  "\u06F6": "6",
  "\u06F7": "7",
  "\u06F8": "8",
  "\u06F9": "9",
  "\u0660": "0",
  "\u0661": "1",
  "\u0662": "2",
  "\u0663": "3",
  "\u0664": "4",
  "\u0665": "5",
  "\u0666": "6",
  "\u0667": "7",
  "\u0668": "8",
  "\u0669": "9"
};
function normalizeDigits(value) {
  return value.replace(/[۰-۹٠-٩]/g, (digit) => DIGIT_MAP[digit] || digit);
}
function normalizePersonnelCode(value) {
  return normalizeDigits(String(value ?? "")).trim().toLocaleUpperCase();
}

// cloudflare/stateBackup.ts
function snapshotCounts(state) {
  return Object.fromEntries(Object.entries(state).filter(([, v]) => Array.isArray(v)).map(([k, v]) => [k, v.length]));
}
function validateSnapshot(state, meta) {
  if (!state || typeof state !== "object" || Array.isArray(state) || Object.keys(sanitizeCloudState(state, true)).length !== Object.keys(state).length) throw Error("Unknown or malformed snapshot keys");
  if (!Number.isSafeInteger(meta?.revision) || meta.revision < 0 || typeof meta.updatedAt !== "string") throw Error("Invalid snapshot revision");
  const unique = (key) => {
    const rows = state[key] || [];
    if (!Array.isArray(rows)) throw Error("Invalid collection " + key);
    const ids = /* @__PURE__ */ new Set();
    for (const row of rows) {
      if (!row || typeof row.id !== "string" || !row.id || ids.has(row.id)) throw Error("Duplicate/missing ID in " + key);
      ids.add(row.id);
    }
    return ids;
  };
  const profiles = unique("pe_profiles");
  unique("pe_criteria");
  const employees = unique("pe_employees");
  const codes = /* @__PURE__ */ new Set();
  for (const e of state.pe_employees || []) {
    if (e.profileId && !profiles.has(String(e.profileId))) throw Error("Orphan personnel profile");
    const c = normalizePersonnelCode(String(e.code || ""));
    if (!c || codes.has(c)) throw Error("Duplicate/missing personnel code");
    codes.add(c);
  }
  for (const key of ["pe_evaluations", "pe_archived_evaluations", "pe_violations"]) {
    unique(key);
    for (const row of state[key] || []) {
      const id = key === "pe_violations" ? row.employeeId : row.empId;
      if (!employees.has(String(id))) throw Error("Orphan relationship " + key);
      if (key !== "pe_violations" && row.profileId && !profiles.has(String(row.profileId))) throw Error("Orphan evaluation profile");
    }
  }
  const opIds = /* @__PURE__ */ new Set();
  if (state.__operation_receipts !== void 0 && !Array.isArray(state.__operation_receipts)) throw Error("Invalid receipt collection");
  for (const op of state.__operation_receipts || []) {
    if (!op.operationId || !op.actorId || !op.payloadHash || !Number.isSafeInteger(op.acceptedRevision) || op.acceptedRevision < 1 || op.acceptedRevision > meta.revision || opIds.has(op.operationId)) throw Error("Invalid/duplicate receipt");
    opIds.add(op.operationId);
  }
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => [k, canonical(v)]));
  return value;
}
async function digest(value) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(canonical(value)))))).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sealSnapshot(state, meta) {
  validateSnapshot(state, meta);
  const normalized = { ...state, __operation_receipts: [...state.__operation_receipts || []].sort((a, b) => a.operationId < b.operationId ? -1 : a.operationId > b.operationId ? 1 : 0) };
  const data = { format: "chalak-state-backup-v1", state: normalized, meta, counts: snapshotCounts(normalized) };
  return { ...data, sha256: await digest(data) };
}
async function verifySnapshot(backup) {
  if (backup?.format !== "chalak-state-backup-v1") throw Error("Unsupported backup");
  validateSnapshot(backup.state, backup.meta);
  const raw = { format: backup.format, state: backup.state, meta: backup.meta, counts: snapshotCounts(backup.state) };
  if (await digest(raw) !== backup.sha256 || JSON.stringify(canonical(raw.counts)) !== JSON.stringify(canonical(backup.counts))) throw Error("Backup checksum/count mismatch");
  const receipts = backup.state.__operation_receipts;
  if (receipts && receipts.every((r, i) => i === 0 || receipts[i - 1].operationId < r.operationId)) return backup;
  return sealSnapshot(backup.state, backup.meta);
}

// tools/state-transfer.ts
var [action, ...args] = process.argv.slice(2);
async function read(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
async function request(url, body) {
  const token = process.env.CHALAK_MAINTENANCE_TOKEN;
  if (!token || token.length < 32) throw Error("Set CHALAK_MAINTENANCE_TOKEN privately");
  const base = new URL(url);
  if (base.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(base.hostname)) throw Error("HTTPS required");
  const r = await fetch(new URL("/api/storage", base), { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const result = await r.json();
  if (!r.ok) throw Error("Maintenance HTTP " + r.status + " " + (result.code || result.error || ""));
  return result;
}
if (action === "seal") {
  const [state, meta, out] = args;
  const backup = await sealSnapshot(await read(state), await read(meta));
  fs.writeFileSync(out, JSON.stringify(backup));
  console.log(JSON.stringify({ backup: out, sha256: backup.sha256, revision: backup.meta.revision, counts: backup.counts }));
} else if (action === "verify") {
  const backup = await verifySnapshot(await read(args[0]));
  console.log(JSON.stringify({ verified: true, sha256: backup.sha256, revision: backup.meta.revision, counts: backup.counts }));
} else if (action === "dry-run" || action === "migrate") {
  const [url, file, execute] = args;
  if (action === "migrate" && execute !== "--execute") throw Error("Explicit --execute and prior owner approval required for migration");
  const backup = await verifySnapshot(await read(file));
  const result = await request(url, { action, backup });
  if (action === "migrate" && result.sha256 !== backup.sha256) throw Error("Migration checksum mismatch");
  console.log(JSON.stringify(result));
} else if (action === "freeze" || action === "activate") {
  const [url, revision, execute] = args;
  if (execute !== "--execute") throw Error("Explicit --execute and prior owner approval required");
  console.log(JSON.stringify(await request(url, { action, expectedRevision: Number(revision) })));
} else if (action === "export") {
  const [url, revision, out] = args;
  const backup = await verifySnapshot(await request(url, { action, expectedRevision: Number(revision) }));
  fs.writeFileSync(out, JSON.stringify(backup));
  console.log(JSON.stringify({ backup: out, revision: backup.meta.revision, sha256: backup.sha256, counts: backup.counts }));
} else if (action === "rollback-kv") {
  const [file, out] = args;
  const backup = await verifySnapshot(await read(file));
  fs.writeFileSync(out, JSON.stringify([{ key: "app_state", value: JSON.stringify(backup.state) }, { key: "app_state_meta", value: JSON.stringify(backup.meta) }]));
  console.log(JSON.stringify({ stagedOnly: true, output: out, revision: backup.meta.revision, sha256: backup.sha256, note: "No KV write or deployment performed; traffic gate and owner approval required before remote restore" }));
} else throw Error("Actions: seal STATE META OUT | verify BACKUP | dry-run URL BACKUP | migrate URL BACKUP --execute | freeze/activate URL REV --execute | export URL REV OUT | rollback-kv BACKUP OUT");
