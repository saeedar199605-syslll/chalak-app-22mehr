var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// ../cloudflare/auth.ts
var SESSION_COOKIE = "chalak_session";
var SESSION_TTL_SECONDS = 8 * 60 * 60;
var encoder = new TextEncoder();
function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}
__name(jsonResponse, "jsonResponse");
function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (rawName === name) {
      try {
        return decodeURIComponent(rawValue.join("="));
      } catch {
        return null;
      }
    }
  }
  return null;
}
__name(getCookie, "getCookie");
async function readSession(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const raw = await env.CHALAK_DB.get(`session:${token}`);
  if (!raw) return null;
  let session;
  try {
    session = JSON.parse(raw);
  } catch {
    await env.CHALAK_DB.delete(`session:${token}`);
    return null;
  }
  if (!session.expiresAt || session.expiresAt <= Date.now()) {
    await env.CHALAK_DB.delete(`session:${token}`);
    return null;
  }
  const currentAuthVersion = Number(await env.CHALAK_DB.get(`credential_version:${normalizeUsername(session.username)}`) || "0");
  if ((session.authVersion ?? 0) !== currentAuthVersion) {
    await env.CHALAK_DB.delete(`session:${token}`);
    return null;
  }
  {
    const state = await readIdentityState(env);
    const employees = Array.isArray(state.pe_employees) ? state.pe_employees : [];
    const employee = employees.find((item) => String(item.id) === session.id && normalizeUsername(item.username) === session.username);
    const lockedUsers = Array.isArray(state.pe_locked_users) ? state.pe_locked_users.map(String) : [];
    const bootstrap = employees.length === 0 && session.id === "emp-admin" && session.username === "admin" && session.role === "admin";
    if (!bootstrap && (!employee || employee.role !== session.role || employee.employmentStatus === "inactive" || employee.employmentStatus === "unknown" || lockedUsers.includes(session.id) || lockedUsers.includes(session.username))) {
      await env.CHALAK_DB.delete(`session:${token}`);
      return null;
    }
  }
  return session;
}
__name(readSession, "readSession");
function normalizeUsername(value) {
  return typeof value === "string" ? value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "") : "";
}
__name(normalizeUsername, "normalizeUsername");

// ../cloudflare/authority.ts
var AUTHORITY_NAME = "chalak-authoritative-state-v1";
function authorityStub(env) {
  if (!env.CHALAK_STATE) throw new Error("transaction_store_unconfigured");
  return env.CHALAK_STATE.get(env.CHALAK_STATE.idFromName(AUTHORITY_NAME));
}
__name(authorityStub, "authorityStub");
async function forwardAuthority(request, env) {
  try {
    return await authorityStub(env).fetch(request);
  } catch {
    return jsonResponse({ error: "\u0645\u0631\u062C\u0639 \u062A\u0631\u0627\u06A9\u0646\u0634\u06CC \u067E\u06CC\u06A9\u0631\u0628\u0646\u062F\u06CC \u0646\u0634\u062F\u0647 \u06CC\u0627 \u0645\u0648\u0642\u062A\u0627\u064B \u062F\u0631 \u062F\u0633\u062A\u0631\u0633 \u0646\u06CC\u0633\u062A\u061B \u0630\u062E\u06CC\u0631\u0647 \u062F\u0631 KV \u0627\u0646\u062C\u0627\u0645 \u0646\u0645\u06CC\u200C\u0634\u0648\u062F.", code: "transaction_store_unavailable", retryable: false }, 503);
  }
}
__name(forwardAuthority, "forwardAuthority");
async function readIdentityState(env) {
  if (env.TRANSACTION_STORE) {
    const { state } = env.TRANSACTION_STORE.read();
    return { pe_employees: state.pe_employees || [], pe_locked_users: state.pe_locked_users || [] };
  }
  const response = await authorityStub(env).fetch(new Request("https://authority/internal/identity"));
  if (!response.ok) throw new Error("authoritative_identity_unavailable");
  return response.json();
}
__name(readIdentityState, "readIdentityState");

// ../functions/api/imports/history.ts
async function onRequestGet({ request, env, data }) {
  const session = data.session;
  if (!session) return jsonResponse({ error: "Authentication required." }, 401);
  if (!env.TRANSACTION_STORE) return forwardAuthority(new Request("https://authority/internal/import-history", { headers: request.headers }), env);
  let state;
  try {
    state = env.TRANSACTION_STORE.read().state;
  } catch {
    return jsonResponse({ error: "\u062A\u0627\u0631\u06CC\u062E\u0686\u0647 \u0648\u0631\u0648\u062F \u0627\u0637\u0644\u0627\u0639\u0627\u062A \u0645\u0648\u0642\u062A\u0627\u064B \u062F\u0631 \u062F\u0633\u062A\u0631\u0633 \u0646\u06CC\u0633\u062A.", code: "import_history_unavailable" }, 503);
  }
  const logs = Array.isArray(state.pe_audit_logs) ? state.pe_audit_logs : [];
  const items = logs.filter((item) => item.action === "source_import_completed" && (session.role === "admin" || item.actorId === session.id)).sort((left, right) => String(right.timestamp || "").localeCompare(String(left.timestamp || ""))).slice(0, 100).map((item) => ({
    id: typeof item.id === "string" ? item.id : "",
    operationId: typeof item.operationId === "string" ? item.operationId : "",
    time: typeof item.timestamp === "string" ? item.timestamp : "",
    actor: session.role === "admin" && typeof item.actorName === "string" ? item.actorName : void 0,
    source: typeof item.importType === "string" ? item.importType : "\u2014",
    period: typeof item.evaluationPeriodId === "string" ? item.evaluationPeriodId : "\u2014",
    rowsRead: Number.isInteger(item.rowsRead) ? item.rowsRead : Number(item.affectedEvaluationCount || 0),
    acceptedRows: Number.isInteger(item.acceptedRows) ? item.acceptedRows : Number(item.affectedEvaluationCount || 0),
    rejectedRows: Number.isInteger(item.rejectedRows) ? item.rejectedRows : 0,
    affectedEvaluations: Number(item.affectedEvaluationCount || 0),
    status: item.result === "accepted" ? "accepted" : "unknown"
  }));
  return jsonResponse({ items });
}
__name(onRequestGet, "onRequestGet");

// index.ts
import { DurableObject } from "cloudflare:workers";

// ../cloudflare/syncState.ts
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
__name(isCloudSyncKey, "isCloudSyncKey");
function sanitizeCloudState(input, includeInternal = false) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (isCloudSyncKey(key) || includeInternal && INTERNAL_STATE_KEYS.has(key)) output[key] = value;
  }
  return output;
}
__name(sanitizeCloudState, "sanitizeCloudState");

// ../cloudflare/operationReceipt.ts
async function stateOperationHash(envelope) {
  const payload = { changes: sanitizeCloudState(envelope.state === void 0 ? envelope : envelope.state), sourceImport: envelope.sourceImport, evaluationPatch: envelope.evaluationPatch === true, employeePatch: envelope.employeePatch === true, evaluationExpected: envelope.evaluationExpected, evaluationDeleteIds: envelope.evaluationDeleteIds };
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(payload))))).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(stateOperationHash, "stateOperationHash");

// ../src/utils/iranDate.ts
var IRAN_TIME_ZONE = "Asia/Tehran";
var jalaliPartsFormatter = new Intl.DateTimeFormat("en-US-u-ca-persian-nu-latn", {
  year: "numeric",
  month: "numeric",
  day: "numeric",
  timeZone: IRAN_TIME_ZONE
});
var jalaliMonthCache = /* @__PURE__ */ new Map();
var tehranWallClockFormatter = new Intl.DateTimeFormat("en-US-u-ca-gregory-nu-latn", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZone: IRAN_TIME_ZONE
});
var tehranGregorianDateFormatter = new Intl.DateTimeFormat("en-US-u-ca-gregory-nu-latn", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  timeZone: IRAN_TIME_ZONE
});
function formatDateKey({ year, month, day }) {
  return `${year}/${String(month).padStart(2, "0")}/${String(day).padStart(2, "0")}`;
}
__name(formatDateKey, "formatDateKey");
function utcWallClockTimestamp(year, month, day, hour, minute, second) {
  const value = /* @__PURE__ */ new Date(0);
  value.setUTCFullYear(year, month - 1, day);
  value.setUTCHours(hour, minute, second, 0);
  return value.getTime();
}
__name(utcWallClockTimestamp, "utcWallClockTimestamp");
function parseTehranWallClock(year, month, day, hour, minute, second) {
  const requestedWallClock = utcWallClockTimestamp(year, month, day, hour, minute, second);
  let candidate = requestedWallClock;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const parts = tehranWallClockFormatter.formatToParts(new Date(candidate));
    const part = /* @__PURE__ */ __name((type) => Number(parts.find((item) => item.type === type)?.value), "part");
    const observedWallClock = utcWallClockTimestamp(
      part("year"),
      part("month"),
      part("day"),
      part("hour"),
      part("minute"),
      part("second")
    );
    const correction = requestedWallClock - observedWallClock;
    candidate += correction;
    if (correction === 0) break;
  }
  return new Date(candidate);
}
__name(parseTehranWallClock, "parseTehranWallClock");
function getJalaliDateParts(date = /* @__PURE__ */ new Date()) {
  const parts = jalaliPartsFormatter.formatToParts(date);
  const read = /* @__PURE__ */ __name((type) => Number(parts.find((part) => part.type === type)?.value), "read");
  return { year: read("year"), month: read("month"), day: read("day") };
}
__name(getJalaliDateParts, "getJalaliDateParts");
function getJalaliDateKey(date = /* @__PURE__ */ new Date()) {
  return formatDateKey(getJalaliDateParts(date));
}
__name(getJalaliDateKey, "getJalaliDateKey");
function getJalaliMonthDates(year, month) {
  if (!Number.isInteger(year) || !Number.isInteger(month) || month < 1 || month > 12) return [];
  const cacheKey = `${year}/${month}`;
  const cached = jalaliMonthCache.get(cacheKey);
  if (cached) return cached;
  const approximateGregorianYear = year + 621;
  const start = Date.UTC(approximateGregorianYear, 0, 1);
  const end = Date.UTC(approximateGregorianYear + 2, 0, 1);
  const dates = [];
  for (let timestamp = start; timestamp < end; timestamp += 24 * 60 * 60 * 1e3) {
    const gregorianDate = new Date(timestamp);
    const parts = getJalaliDateParts(gregorianDate);
    if (parts.year !== year || parts.month !== month) continue;
    const weekdayIndex = (gregorianDate.getUTCDay() + 1) % 7;
    dates.push({ ...parts, dateStr: formatDateKey(parts), weekdayIndex, gregorianDate });
  }
  jalaliMonthCache.set(cacheKey, dates);
  return dates;
}
__name(getJalaliMonthDates, "getJalaliMonthDates");
function jalaliDateKeyToGregorianICSDate(dateKey) {
  const match = /^(\d{4})\/(\d{2})\/(\d{2})$/.exec(dateKey.trim());
  if (!match) return void 0;
  const [, yearText, monthText, dayText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  if (month < 1 || month > 12 || day < 1) return void 0;
  const matchDate = getJalaliMonthDates(year, month).find((candidate) => candidate.day === day);
  if (!matchDate) return void 0;
  const gregorian = matchDate.gregorianDate;
  return `${gregorian.getUTCFullYear()}${String(gregorian.getUTCMonth() + 1).padStart(2, "0")}${String(gregorian.getUTCDate()).padStart(2, "0")}`;
}
__name(jalaliDateKeyToGregorianICSDate, "jalaliDateKeyToGregorianICSDate");
function parseTehranDateInput(value, boundary = "start") {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return void 0;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year < 1 || month < 1 || month > 12 || day < 1) return void 0;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (day > daysInMonth) return void 0;
  const isEnd = boundary === "end";
  const parsed = parseTehranWallClock(year, month, day, isEnd ? 23 : 0, isEnd ? 59 : 0, isEnd ? 59 : 0);
  if (Number.isNaN(parsed.getTime())) return void 0;
  if (boundary === "end") parsed.setMilliseconds(999);
  return parsed;
}
__name(parseTehranDateInput, "parseTehranDateInput");

// ../src/utils/personnelSearch.ts
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
__name(normalizeDigits, "normalizeDigits");
function normalizePersonnelCode(value) {
  return normalizeDigits(String(value ?? "")).trim().toLocaleUpperCase();
}
__name(normalizePersonnelCode, "normalizePersonnelCode");

// ../src/utils/businessDate.ts
function parseBusinessDate(value) {
  if (typeof value !== "string") return void 0;
  const m = /^(\d{4})\/(\d{1,2})\/(\d{1,2})$/.exec(normalizeDigits(value).trim());
  if (!m || Number(m[1]) < 1300 || Number(m[1]) > 1600) return void 0;
  const key = `${m[1]}/${m[2].padStart(2, "0")}/${m[3].padStart(2, "0")}`;
  const date = jalaliDateKeyToGregorianICSDate(key);
  return date ? parseTehranDateInput(`${date.slice(0, 4)}-${date.slice(4, 6)}-${date.slice(6, 8)}`) : void 0;
}
__name(parseBusinessDate, "parseBusinessDate");

// ../src/utils/authorization.ts
var WORKFLOW_STAGE_ORDER = [
  "self_review",
  "supervisor_review",
  "peer_review",
  "calibration_review",
  "hr_approval",
  "feedback_meeting",
  "completed"
];
var DEFAULT_WORKFLOW_CEILINGS = {
  admin: "completed",
  supervisor: "supervisor_review",
  employee: "self_review"
};
var grant = /* @__PURE__ */ __name((type) => ({ type }), "grant");
var DEFAULT_ROLE_GRANTS = {
  admin: {},
  supervisor: {
    violations: { view: grant("own") },
    evaluations: { view: grant("authorized_employees"), edit: grant("authorized_employees"), submit: grant("authorized_employees"), advance_workflow: grant("authorized_employees") },
    mis: { view: grant("authorized_employees") },
    workflow: { view: grant("authorized_employees"), submit: grant("authorized_employees"), return: grant("authorized_employees"), approve: grant("authorized_employees"), reassign: grant("authorized_employees"), delegate: grant("authorized_employees"), advance_workflow: grant("authorized_employees") },
    cartable: { view: grant("authorized_employees"), advance_workflow: grant("authorized_employees") },
    reports: { view: grant("authorized_employees"), export: grant("authorized_employees") },
    analytics: { view: grant("authorized_employees") },
    support: { view: grant("own"), create: grant("own") },
    onboarding: { view: grant("own") }
  },
  employee: {
    violations: { view: grant("own") },
    evaluations: { view: grant("own"), edit: grant("own"), submit: grant("own") },
    workflow: { view: grant("own"), submit: grant("own") },
    cartable: { view: grant("own") },
    support: { view: grant("own"), create: grant("own") },
    onboarding: { view: grant("own") }
  }
};
var DEFAULT_GRANULAR_PERMISSION_POLICY = {
  version: 1,
  workflowCeilings: DEFAULT_WORKFLOW_CEILINGS
};
function readGranularPermissionPolicy() {
  try {
    if (typeof localStorage === "undefined") return DEFAULT_GRANULAR_PERMISSION_POLICY;
    const value = localStorage.getItem("pe_granular_permissions");
    if (!value) return DEFAULT_GRANULAR_PERMISSION_POLICY;
    const parsed = JSON.parse(value);
    return parsed.version === 1 ? { ...DEFAULT_GRANULAR_PERMISSION_POLICY, ...parsed } : DEFAULT_GRANULAR_PERMISSION_POLICY;
  } catch {
    return DEFAULT_GRANULAR_PERMISSION_POLICY;
  }
}
__name(readGranularPermissionPolicy, "readGranularPermissionPolicy");
function getEffectivePermissionGrant(policy, user, module, capability) {
  const userGrants = policy.users?.[user.id]?.[module];
  if (userGrants && Object.prototype.hasOwnProperty.call(userGrants, capability)) return userGrants[capability] ?? null;
  const roleGrants = policy.roles?.[user.role]?.[module];
  if (roleGrants && Object.prototype.hasOwnProperty.call(roleGrants, capability)) return roleGrants[capability] ?? null;
  return DEFAULT_ROLE_GRANTS[user.role]?.[module]?.[capability] ?? null;
}
__name(getEffectivePermissionGrant, "getEffectivePermissionGrant");
function employeeWithinScope(actor, subject, grantScope) {
  switch (grantScope.type) {
    case "all":
      return actor.role === "admin";
    case "own":
      return subject.id === actor.id;
    case "direct_reports":
      return subject.supervisorId === actor.id;
    case "own_unit":
      return Boolean(actor.unit && subject.unit === actor.unit && (subject.supervisorId === actor.id || !subject.supervisorId));
    case "selected_units":
      return grantScope.unitIds.includes(subject.unit);
    case "authorized_employees": {
      const ids = grantScope.employeeIds || [];
      if (ids.length) return ids.includes(subject.id);
      return subject.id === actor.id || subject.supervisorId === actor.id || !subject.supervisorId && subject.unit === actor.unit || subject.peerReviewerId === actor.id || subject.calibrationLeadId === actor.id || subject.approverId === actor.id || subject.hrPartnerId === actor.id;
    }
  }
}
__name(employeeWithinScope, "employeeWithinScope");
function authorize(actor, module, capability, subject, policy = readGranularPermissionPolicy()) {
  if (actor.role === "admin") return { allowed: true, scope: grant("all"), reason: "administrator" };
  const permission = getEffectivePermissionGrant(policy, actor, module, capability);
  if (!permission) return { allowed: false, reason: `missing ${module}.${capability} grant` };
  if (!subject) return { allowed: true, scope: permission, reason: "capability granted" };
  if (!employeeWithinScope(actor, subject, permission)) return { allowed: false, scope: permission, reason: "outside authorized employee scope" };
  return { allowed: true, scope: permission, reason: "capability and scope granted" };
}
__name(authorize, "authorize");
var IMPORT_AUTHORIZATION = {
  employee: { module: "employees", capability: "employee_import" },
  criteria: { module: "criteria", capability: "criteria_import" },
  mis: { module: "mis", capability: "mis_import" },
  kasra: { module: "mis", capability: "kasra_import" }
};
function canImport(actor, importType, subject, policy = readGranularPermissionPolicy()) {
  const target = IMPORT_AUTHORIZATION[importType];
  return authorize(actor, target.module, target.capability, subject, policy);
}
__name(canImport, "canImport");
function getWorkflowCeiling(actor, policy = readGranularPermissionPolicy()) {
  return policy.userWorkflowCeilings?.[actor.id] ?? policy.workflowCeilings?.[actor.role] ?? DEFAULT_WORKFLOW_CEILINGS[actor.role];
}
__name(getWorkflowCeiling, "getWorkflowCeiling");
function isWithinWorkflowCeiling(actor, stage, policy = readGranularPermissionPolicy()) {
  if (actor.role === "admin") return true;
  const normalized = stage === "rejected" ? actor.role === "employee" ? "self_review" : "supervisor_review" : stage === "appealed" ? "feedback_meeting" : stage;
  const stageIndex = WORKFLOW_STAGE_ORDER.indexOf(normalized);
  const ceilingIndex = WORKFLOW_STAGE_ORDER.indexOf(getWorkflowCeiling(actor, policy));
  return stageIndex >= 0 && ceilingIndex >= 0 && stageIndex <= ceilingIndex;
}
__name(isWithinWorkflowCeiling, "isWithinWorkflowCeiling");
function canAccessWorkflowStage(actor, stage, capability, policy = readGranularPermissionPolicy()) {
  if (actor.role === "admin") return true;
  const configured = policy.userWorkflowStageCapabilities?.[actor.id]?.[stage]?.[capability] ?? policy.workflowStageCapabilities?.[actor.role]?.[stage]?.[capability];
  if (typeof configured === "boolean") return configured;
  if (capability === "view" || capability === "act") return true;
  if (capability === "edit") return actor.role === "supervisor" ? stage === "supervisor_review" || stage === "feedback_meeting" : stage === "self_review" || stage === "rejected";
  return actor.role === "supervisor" ? stage === "supervisor_review" : stage === "self_review" || stage === "rejected";
}
__name(canAccessWorkflowStage, "canAccessWorkflowStage");

// ../src/utils/workflowPolicy.ts
var HSE_ROUTEABLE_STAGES = [
  "supervisor_review",
  "peer_review",
  "calibration_review"
];
var HSE_RETURNABLE_STAGES = HSE_ROUTEABLE_STAGES;
var stageNext = {
  self_review: ["supervisor_review"],
  supervisor_review: ["peer_review", "calibration_review"],
  peer_review: ["calibration_review"],
  calibration_review: ["hr_approval"],
  hr_approval: ["feedback_meeting"],
  feedback_meeting: ["completed"],
  rejected: ["supervisor_review"],
  appealed: ["feedback_meeting"]
};
function isValidWorkflowEdge(from, to, action, role) {
  if (from === "hse_review" || to === "hse_review") {
    if (action === "route_hse") return (role === "admin" || role === "supervisor") && HSE_ROUTEABLE_STAGES.includes(from) && to === "hse_review";
    if (action === "complete_hse_review") return from === "hse_review" && HSE_RETURNABLE_STAGES.includes(to);
    return false;
  }
  if (action === "admin_override") return role === "admin";
  if (action === "reassign_assignee") return from === to;
  if (action === "reject_to_supervisor" || action === "reject_to_employee") return to === "rejected" && ["supervisor_review", "peer_review", "calibration_review", "hr_approval"].includes(from);
  if (action === "submit_appeal") return role === "employee" && ["supervisor_review", "feedback_meeting", "completed"].includes(from) && to === "appealed";
  if (action === "resolve_appeal") return from === "appealed" && to === "feedback_meeting";
  if (action === "submit_self") return role === "employee" && from === "self_review" && to === "supervisor_review";
  if (action === "submit_supervisor") return role === "employee" ? from === "rejected" && to === "supervisor_review" : (from === "supervisor_review" || from === "rejected") && ["calibration_review", "peer_review"].includes(to);
  if (action === "submit_peer") return from === "peer_review" && to === "calibration_review";
  if (action === "approve_calibration") return from === "calibration_review" && to === "hr_approval";
  if (action === "approve_hr") return from === "hr_approval" && to === "feedback_meeting";
  if (action === "complete_feedback") return from === "feedback_meeting" && to === "completed";
  if (action === "advance") return (stageNext[from] || []).includes(to);
  return false;
}
__name(isValidWorkflowEdge, "isValidWorkflowEdge");

// ../src/utils/workflowAuthorization.ts
function workflowPermissionForTransition(action, fromStage) {
  switch (action) {
    case "submit_self":
    case "advance":
      return "advance";
    case "submit_supervisor":
      return fromStage === "rejected" ? "advance" : "approve";
    case "submit_peer":
    case "approve_calibration":
    case "approve_hr":
    case "resolve_appeal":
      return "approve";
    case "complete_feedback":
      return "finalize";
    case "submit_appeal":
      return "appeal";
    case "reject_to_supervisor":
    case "reject_to_employee":
      return "reject";
    case "reassign_assignee":
      return "reassign";
    case "admin_override":
      return "override";
    case "route_hse":
      return "route_hse";
    case "complete_hse_review":
      return "complete_hse_review";
    default:
      return null;
  }
}
__name(workflowPermissionForTransition, "workflowPermissionForTransition");
function workflowTaskIdentity(evaluation) {
  return `${evaluation.id}:${evaluation.stage || "self_review"}:${evaluation.currentAssigneeId || "unassigned"}`;
}
__name(workflowTaskIdentity, "workflowTaskIdentity");
function isExplicitlyReassigned(evaluation) {
  return Boolean(evaluation.currentAssigneeId && evaluation.history?.[0]?.action === "reassign_assignee");
}
__name(isExplicitlyReassigned, "isExplicitlyReassigned");
function isWithinSupervisorScope(supervisor, employee, allEmployees) {
  if (supervisor.role !== "supervisor" && supervisor.role !== "admin") return false;
  if (supervisor.role === "admin") return true;
  if (employee.supervisorId === supervisor.id) return true;
  if (!employee.supervisorId && employee.unit === supervisor.unit) return true;
  return false;
}
__name(isWithinSupervisorScope, "isWithinSupervisorScope");
function isDelegationActive(delegation, now = Date.now()) {
  if (delegation.status === "revoked") return false;
  if (delegation.status === "expired") return false;
  if (now < delegation.startDate) return false;
  if (now > delegation.endDate) return false;
  return true;
}
__name(isDelegationActive, "isDelegationActive");
function hasActiveDelegation(user, evaluation, action, delegations, employees, now = Date.now()) {
  const activeDelegations = delegations.filter(
    (d) => isDelegationActive(d, now) && d.delegateId === user.id && d.action === action
  );
  for (const delegation of activeDelegations) {
    const delegator = employees.find((e) => e.id === delegation.delegatorId);
    if (!delegator) {
      continue;
    }
    if (isExplicitlyReassigned(evaluation) && delegator.role !== "admin" && evaluation.currentAssigneeId !== delegator.id) continue;
    if (delegator.role === "admin") {
    } else {
      if (!canDelegate(delegator, action, employees, delegations)) {
        continue;
      }
      if (delegation.scope === "employee") {
        const targetEmp = employees.find((e) => e.id === delegation.targetEmpId);
        if (targetEmp && !isWithinSupervisorScope(delegator, targetEmp, employees)) {
          continue;
        }
      }
      if (delegation.scope === "unit" && delegation.targetUnit) {
        const hasScope = employees.some(
          (e) => e.unit === delegation.targetUnit && isWithinSupervisorScope(delegator, e, employees)
        );
        if (!hasScope) {
          continue;
        }
      }
    }
    if (delegation.scope === "system") {
      return { granted: true, delegation };
    }
    if (delegation.scope === "employee" && delegation.targetEmpId === evaluation.empId) {
      return { granted: true, delegation };
    }
    if (delegation.scope === "unit") {
      const emp = employees.find((e) => e.id === evaluation.empId);
      if (emp && emp.unit === delegation.targetUnit) {
        return { granted: true, delegation };
      }
    }
  }
  return { granted: false };
}
__name(hasActiveDelegation, "hasActiveDelegation");
function getStagesForUserAction(userRole, action) {
  switch (userRole) {
    case "admin":
      return ["self_review", "supervisor_review", "peer_review", "calibration_review", "hr_approval", "feedback_meeting", "rejected", "appealed"];
    case "supervisor":
      switch (action) {
        case "approve":
          return ["supervisor_review", "peer_review", "calibration_review", "hr_approval", "feedback_meeting", "appealed"];
        case "finalize":
          return ["feedback_meeting"];
        case "reject":
          return ["supervisor_review", "peer_review", "calibration_review", "hr_approval"];
        case "advance":
          return ["supervisor_review"];
        case "reassign":
          return ["supervisor_review", "peer_review", "calibration_review", "hr_approval", "feedback_meeting", "rejected", "appealed"];
        case "override":
          return [];
        default:
          return [];
      }
    case "employee":
      switch (action) {
        case "advance":
          return ["self_review", "rejected"];
        case "approve":
          return ["peer_review"];
        default:
          return [];
      }
    default:
      return [];
  }
}
__name(getStagesForUserAction, "getStagesForUserAction");
function canPerformWorkflowAction(user, evaluation, action, opts = {}) {
  const employees = opts.employees || [];
  const delegations = opts.delegations || [];
  const policy = opts.permissionPolicy || readGranularPermissionPolicy();
  const now = Date.now();
  const emp = employees.find((e) => e.id === evaluation.empId);
  if (user.role === "admin") {
    return { authorized: true, reason: "\u0633\u06CC\u0633\u062A\u0645 \u0645\u062F\u06CC\u0631 \u0627\u0631\u0634\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  const currentStage = evaluation.stage || "self_review";
  if (action === "route_hse") {
    const permittedFrom = HSE_ROUTEABLE_STAGES.includes(currentStage);
    const reviewerExists = Boolean(emp?.hseReviewerId && (opts.allowUnlistedHseReviewer || employees.some((person) => person.id === emp.hseReviewerId)));
    if (user.role !== "supervisor" || !permittedFrom || !reviewerExists || evaluation.status === "locked" || currentStage === "completed") {
      return { authorized: false, reason: !reviewerExists ? "\u0628\u0631\u0627\u06CC \u0627\u06CC\u0646 \u0647\u0645\u06A9\u0627\u0631 \u0628\u0627\u0632\u0628\u06CC\u0646 HSE \u062A\u0639\u06CC\u06CC\u0646 \u0646\u0634\u062F\u0647 \u0627\u0633\u062A" : "\u0627\u0631\u0633\u0627\u0644 \u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0647 HSE \u062F\u0631 \u0627\u06CC\u0646 \u0648\u0636\u0639\u06CC\u062A \u0645\u062C\u0627\u0632 \u0646\u06CC\u0633\u062A", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
    }
    if (!emp || evaluation.currentAssigneeId !== user.id || !isWithinSupervisorScope(user, emp, employees)) {
      return { authorized: false, reason: "\u0641\u0642\u0637 \u0645\u0633\u0626\u0648\u0644 \u0645\u062C\u0627\u0632 \u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647 \u0645\u06CC\u200C\u062A\u0648\u0627\u0646\u062F \u062F\u0631\u062E\u0648\u0627\u0633\u062A \u0628\u0631\u0631\u0633\u06CC HSE \u062B\u0628\u062A \u06A9\u0646\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
    }
    if (!canAccessWorkflowStage(user, currentStage, "act", policy) || !isWithinWorkflowCeiling(user, currentStage, policy)) {
      return { authorized: false, reason: "\u062F\u0631 \u0645\u0631\u062D\u0644\u0647 \u0641\u0639\u0644\u06CC \u0627\u062C\u0627\u0632\u0647 \u0627\u0631\u0633\u0627\u0644 \u0628\u0647 HSE \u0646\u062F\u0627\u0631\u06CC\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
    }
    const grant2 = authorize(user, "workflow", "route_hse", emp, policy);
    return { authorized: grant2.allowed, reason: grant2.reason, author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  if (action === "complete_hse_review") {
    const context = evaluation.hseReviewContext;
    const allowed = currentStage === "hse_review" && evaluation.status !== "locked" && context?.hseReviewerId === user.id && evaluation.currentAssigneeId === user.id && canAccessWorkflowStage(user, "hse_review", "act", policy);
    return { authorized: allowed, reason: allowed ? "\u0628\u0627\u0632\u0628\u06CC\u0646 \u062A\u0639\u06CC\u06CC\u0646\u200C\u0634\u062F\u0647 HSE" : "\u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647 \u062F\u0631 \u0627\u062E\u062A\u06CC\u0627\u0631 \u0628\u0627\u0632\u0628\u06CC\u0646 \u062A\u0639\u06CC\u06CC\u0646\u200C\u0634\u062F\u0647 HSE \u0646\u06CC\u0633\u062A", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  const exceedsCeiling = user.role === "supervisor" && (!isWithinWorkflowCeiling(user, currentStage, policy) || Boolean(opts.targetStage && !isWithinWorkflowCeiling(user, opts.targetStage, policy)));
  if (exceedsCeiling || !canAccessWorkflowStage(user, currentStage, "act", policy)) {
    return { authorized: false, reason: `\u0633\u0637\u062D \u0627\u062E\u062A\u06CC\u0627\u0631 \u06AF\u0631\u062F\u0634 \u06A9\u0627\u0631 \u0634\u0645\u0627 \u062A\u0627 \xAB${getWorkflowCeiling(user, policy)}\xBB \u062A\u0646\u0638\u06CC\u0645 \u0634\u062F\u0647 \u0627\u0633\u062A`, author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  const capability = action === "advance" ? user.role === "employee" ? "submit" : "advance_workflow" : action === "reject" ? "return" : action === "finalize" ? "finalize" : action === "approve" ? "approve" : action === "reassign" ? "reassign" : action === "appeal" ? "submit" : "finalize";
  const deleg = hasActiveDelegation(user, evaluation, action, delegations, employees, now);
  if (deleg.granted && deleg.delegation) {
    const validStages = getStagesForUserAction(user.role, action);
    const currentStage2 = evaluation.stage || "self_review";
    if (validStages.includes(currentStage2)) {
      if (!canAccessWorkflowStage(user, currentStage2, action === "advance" ? "advance" : "act", policy)) {
        return { authorized: false, reason: "\u062F\u0631 \u0627\u06CC\u0646 \u0645\u0631\u062D\u0644\u0647 \u0645\u062C\u0648\u0632 \u0627\u0642\u062F\u0627\u0645 \u06CC\u0627 \u067E\u06CC\u0634\u0628\u0631\u062F \u06AF\u0631\u062F\u0634 \u06A9\u0627\u0631 \u0646\u062F\u0627\u0631\u06CC\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
      }
      return { authorized: true, reason: `\u062A\u0641\u0648\u06CC\u0636 \u0627\u0632 \u0637\u0631\u0641 ${deleg.delegation.delegatorId}`, delegation: deleg.delegation, author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
    }
  }
  const employeeOwnAppeal = user.role === "employee" && action === "appeal" && emp?.id === user.id && ["supervisor_review", "feedback_meeting", "completed"].includes(currentStage);
  if (evaluation.currentAssigneeId && evaluation.currentAssigneeId !== user.id && !employeeOwnAppeal) {
    return { authorized: false, reason: "\u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0647 \u0645\u0633\u0626\u0648\u0644 \u062F\u06CC\u06AF\u0631\u06CC \u0648\u0627\u06AF\u0630\u0627\u0631 \u0634\u062F\u0647 \u0627\u0633\u062A", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  const grantModule = action === "advance" || action === "appeal" ? "evaluations" : "workflow";
  const isCurrentReassignedOwner = isExplicitlyReassigned(evaluation) && evaluation.currentAssigneeId === user.id;
  const policyCheck = emp ? authorize(user, grantModule, capability, isCurrentReassignedOwner ? void 0 : emp, policy) : { allowed: false, reason: "employee record unavailable" };
  if (!policyCheck.allowed) {
    return { authorized: false, reason: policyCheck.reason, author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  if (isExplicitlyReassigned(evaluation) && evaluation.currentAssigneeId !== user.id) {
    return { authorized: false, reason: "\u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0647 \u0645\u0633\u0626\u0648\u0644 \u062F\u06CC\u06AF\u0631\u06CC \u0648\u0627\u06AF\u0630\u0627\u0631 \u0634\u062F\u0647 \u0627\u0633\u062A", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  if (isExplicitlyReassigned(evaluation) && evaluation.currentAssigneeId === user.id) {
    const stage = evaluation.stage || "self_review";
    if (getStagesForUserAction(user.role, action).includes(stage)) {
      if (!canAccessWorkflowStage(user, stage, action === "advance" ? "advance" : "act", policy)) {
        return { authorized: false, reason: "\u062F\u0631 \u0627\u06CC\u0646 \u0645\u0631\u062D\u0644\u0647 \u0645\u062C\u0648\u0632 \u0627\u0642\u062F\u0627\u0645 \u06CC\u0627 \u067E\u06CC\u0634\u0628\u0631\u062F \u06AF\u0631\u062F\u0634 \u06A9\u0627\u0631 \u0646\u062F\u0627\u0631\u06CC\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
      }
      return { authorized: true, reason: "\u0645\u0633\u0626\u0648\u0644 \u0645\u062C\u0627\u0632 \u0648\u0627\u06AF\u0630\u0627\u0631\u0634\u062F\u0647", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
    }
  }
  if (user.role === "employee") {
    if (emp?.peerReviewerId === user.id && evaluation.currentAssigneeId === user.id && currentStage === "peer_review" && action === "approve") {
      return { authorized: true, reason: "\u0627\u0631\u0632\u06CC\u0627\u0628 \u0647\u0645\u062A\u0627\u06CC \u062A\u0639\u06CC\u06CC\u0646\u200C\u0634\u062F\u0647", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
    }
    if (emp?.id === user.id) {
      if ((evaluation.stage === "self_review" || evaluation.stage === "rejected") && action === "advance") {
        return { authorized: true, reason: "\u062E\u0648\u062F\u0627\u0631\u0632\u06CC\u0627\u0628\u06CC", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
      }
      if (["supervisor_review", "feedback_meeting", "completed"].includes(currentStage) && action === "appeal") {
        return { authorized: true, reason: "\u0641\u0631\u062C\u0627\u0645\u200C\u062E\u0648\u0627\u0647\u06CC", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
      }
      return { authorized: false, reason: "\u0634\u0645\u0627 \u0635\u0644\u0627\u062D\u06CC\u062A \u0627\u0646\u062C\u0627\u0645 \u0627\u06CC\u0646 \u0639\u0645\u0644\u06CC\u0627\u062A \u0631\u0627 \u0646\u062F\u0627\u0631\u06CC\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
    }
    return { authorized: false, reason: "\u0634\u0645\u0627 \u0635\u0644\u0627\u062D\u06CC\u062A \u0627\u0646\u062C\u0627\u0645 \u0627\u06CC\u0646 \u0639\u0645\u0644\u06CC\u0627\u062A \u0631\u0627 \u0646\u062F\u0627\u0631\u06CC\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  if (user.role === "supervisor") {
    const stage = evaluation.stage || "self_review";
    if (policyCheck.allowed) {
      const validStages = getStagesForUserAction(user.role, action);
      if (validStages.includes(stage)) {
        if (!canAccessWorkflowStage(user, stage, action === "advance" ? "advance" : "act", policy)) {
          return { authorized: false, reason: "\u062F\u0631 \u0627\u06CC\u0646 \u0645\u0631\u062D\u0644\u0647 \u0645\u062C\u0648\u0632 \u0627\u0642\u062F\u0627\u0645 \u06CC\u0627 \u067E\u06CC\u0634\u0628\u0631\u062F \u06AF\u0631\u062F\u0634 \u06A9\u0627\u0631 \u0646\u062F\u0627\u0631\u06CC\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
        }
        return { authorized: true, reason: "\u0645\u062C\u0648\u0632 \u0648 \u062F\u0627\u0645\u0646\u0647 \u0633\u0627\u0632\u0645\u0627\u0646\u06CC \u062A\u0646\u0638\u06CC\u0645\u200C\u0634\u062F\u0647", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
      }
      return {
        authorized: false,
        reason: `\u062F\u0631 \u0645\u0631\u062D\u0644\u0647 \xAB${stage}\xBB \u0627\u062C\u0627\u0632\u0647 \u0627\u0646\u062C\u0627\u0645 \u0627\u06CC\u0646 \u0639\u0645\u0644\u06CC\u0627\u062A \u0646\u062F\u0627\u0631\u06CC\u062F`,
        author: { actorId: user.id, actorName: user.name, actorRole: user.role }
      };
    }
    return { authorized: false, reason: "\u067E\u0631\u0633\u0646\u0644\u06CC \u062F\u0631 \u0627\u062E\u062A\u06CC\u0627\u0631 \u0646\u062F\u0627\u0631\u06CC\u062F", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
  }
  return { authorized: false, reason: "\u0646\u0642\u0634 \u0646\u0627\u0634\u0646\u0627\u062E\u062A\u0647", author: { actorId: user.id, actorName: user.name, actorRole: user.role } };
}
__name(canPerformWorkflowAction, "canPerformWorkflowAction");
function canDelegate(delegator, action, employees, delegations) {
  if (delegator.role === "admin") return true;
  if (delegator.role === "supervisor") {
    return ["advance", "reject", "approve", "reassign"].includes(action);
  }
  if (delegator.role === "employee") {
    return action === "advance";
  }
  return false;
}
__name(canDelegate, "canDelegate");

// ../src/types.ts
var NEED_DOCUMENT_SCORES = [1, 2, 5];
var DEFAULT_ROUTE_RULES = [
  {
    id: "route-default-workshop",
    title: "\u0645\u0633\u06CC\u0631 \u0627\u0633\u062A\u0627\u0646\u062F\u0627\u0631\u062F \u0645\u0634\u0627\u063A\u0644 \u06A9\u0627\u0631\u06AF\u0627\u0647\u06CC \u0648 \u062A\u0648\u0644\u06CC\u062F\u06CC",
    unit: "all",
    profileId: "all",
    requiresSelfReview: false,
    requiresSupervisorReview: true,
    requiresCalibration: true,
    requiresHrApproval: true,
    autoAdvanceOnPass: false
  },
  {
    id: "route-fast-track",
    title: "\u0645\u0633\u06CC\u0631 \u0633\u0631\u06CC\u0639 \u067E\u0631\u0633\u0646\u0644 \u0645\u0648\u0642\u062A \u06CC\u0627 \u0622\u0632\u0645\u0627\u06CC\u0634\u06CC",
    unit: "all",
    requiresSelfReview: false,
    requiresSupervisorReview: true,
    requiresCalibration: false,
    requiresHrApproval: true,
    autoAdvanceOnPass: true
  }
];

// ../src/utils/scoreSemantics.ts
function statusFieldFor(field) {
  return field === "value" ? "scoreStatus" : field === "self" ? "selfScoreStatus" : "peerScoreStatus";
}
__name(statusFieldFor, "statusFieldFor");
function getScoreDisposition(score, field = "value") {
  const explicit = score[statusFieldFor(field)];
  if (explicit) return explicit;
  const value = score[field];
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? "scored" : "pending";
}
__name(getScoreDisposition, "getScoreDisposition");
function isNumericScoreRecorded(score, field = "value") {
  return getScoreDisposition(score, field) === "scored" && typeof score[field] === "number" && Number.isFinite(score[field]);
}
__name(isNumericScoreRecorded, "isNumericScoreRecorded");
function isScoreDispositionComplete(score, field = "value") {
  const disposition = getScoreDisposition(score, field);
  if (disposition === "not_applicable" || disposition === "exempt") return true;
  return disposition === "scored" && isNumericScoreRecorded(score, field);
}
__name(isScoreDispositionComplete, "isScoreDispositionComplete");

// ../src/utils/formulaEngine.ts
function calculateMultiSourceCompositeScore(criterion, breakdown) {
  const config = criterion.multiSourceConfig;
  if (!config || !config.items || config.items.length === 0) {
    const available = [
      breakdown.misScore,
      breakdown.kasraScore,
      breakdown.supervisorScore,
      breakdown.systemScore
    ].filter((s) => s !== void 0 && s > 0);
    if (available.length === 0) return { score: 0, docText: "", effectivePercentage: 0 };
    const avg = available.reduce((a, b) => a + b, 0) / available.length;
    const rounded = Math.round(avg * 10) / 10;
    return {
      score: rounded,
      docText: `\u0645\u06CC\u0627\u0646\u06AF\u06CC\u0646 \u062A\u0631\u06A9\u06CC\u0628\u06CC \u0645\u0646\u0627\u0628\u0639: ${rounded}`,
      effectivePercentage: 100
    };
  }
  let totalWeightedScore = 0;
  let totalAppliedWeight = 0;
  const partsSummary = [];
  config.items.forEach((item) => {
    let sourceScore = void 0;
    let sourceName = item.label || "";
    if (item.source === "mis") {
      sourceScore = breakdown.misScore;
      if (!sourceName) sourceName = "\u0633\u0627\u0645\u0627\u0646\u0647 \u062A\u0648\u0644\u06CC\u062F MIS";
    } else if (item.source === "kasra") {
      sourceScore = breakdown.kasraScore;
      if (!sourceName) sourceName = "\u062D\u0636\u0648\u0631 \u0648 \u063A\u06CC\u0627\u0628 \u06A9\u0633\u0631\u06CC";
    } else if (item.source === "supervisor") {
      sourceScore = breakdown.supervisorScore;
      if (!sourceName) sourceName = "\u0627\u0631\u0632\u06CC\u0627\u0628\u06CC \u0633\u0631\u067E\u0631\u0633\u062A";
    } else if (item.source === "system") {
      sourceScore = breakdown.systemScore;
      if (!sourceName) sourceName = "\u0641\u0631\u0645\u0648\u0644 \u0633\u06CC\u0633\u062A\u0645\u06CC";
    }
    if (sourceScore !== void 0 && sourceScore > 0) {
      totalWeightedScore += sourceScore * item.weightPercent;
      totalAppliedWeight += item.weightPercent;
      partsSummary.push(`${sourceName} (${item.weightPercent}\u066A): ${sourceScore}`);
    } else {
      partsSummary.push(`${sourceName} (${item.weightPercent}\u066A): \u062F\u0631 \u0627\u0646\u062A\u0638\u0627\u0631`);
    }
  });
  if (totalAppliedWeight === 0) {
    return { score: 0, docText: "\u062F\u0631 \u0627\u0646\u062A\u0638\u0627\u0631 \u0648\u0631\u0648\u062F \u062F\u0627\u062F\u0647 \u0627\u0632 \u0645\u0646\u0627\u0628\u0639 \u0645\u0631\u0628\u0648\u0637\u0647", effectivePercentage: 0 };
  }
  const finalScore = Math.round(totalWeightedScore / totalAppliedWeight * 10) / 10;
  return {
    score: Math.min(5, Math.max(1, finalScore)),
    docText: partsSummary.join(" | "),
    effectivePercentage: totalAppliedWeight
  };
}
__name(calculateMultiSourceCompositeScore, "calculateMultiSourceCompositeScore");

// ../src/utils/workflowAssignee.ts
function resolveWorkflowAssignee(stage, employee, employees) {
  if (!employee) return { id: "unknown", name: "\u0646\u0627\u0645\u0634\u062E\u0635", role: "admin", code: "---", unit: "---", title: "---" };
  const admin = employees.find((person) => person.role === "admin");
  const supervisor = employees.find((person) => person.id === employee.supervisorId) || employees.find((person) => person.unit === employee.unit && person.role === "supervisor" && person.id !== employee.id);
  const assigned = /* @__PURE__ */ __name((id, fallback, synthetic) => {
    const person = (id ? employees.find((candidate) => candidate.id === id) : void 0) || fallback;
    return person ? { id: person.id, name: person.name, role: person.role, code: person.code, unit: person.unit, title: synthetic.title } : synthetic;
  }, "assigned");
  switch (stage) {
    case "self_review":
      return { id: employee.id, name: employee.name, role: employee.role, code: employee.code, unit: employee.unit, title: "\u0634\u0627\u063A\u0644 (\u062B\u0628\u062A \u062E\u0648\u062F\u0627\u0631\u0632\u06CC\u0627\u0628\u06CC)" };
    case "supervisor_review":
      return assigned(employee.supervisorId, supervisor || admin || employees[0], { id: "unknown", name: "\u0633\u0631\u067E\u0631\u0633\u062A \u062A\u0639\u06CC\u06CC\u0646 \u0646\u0634\u062F\u0647", role: "admin", code: "---", unit: employee.unit, title: "\u0645\u0633\u0626\u0648\u0644 \u0627\u0631\u0632\u06CC\u0627\u0628\u06CC \u0633\u0631\u067E\u0631\u0633\u062A" });
    case "peer_review": {
      const peer = employees.find((person) => person.id === employee.peerReviewerId) || employees.find((person) => person.unit === employee.unit && person.id !== employee.id);
      return assigned(peer?.id, void 0, { id: "peer-auto", name: "\u0627\u0631\u0632\u06CC\u0627\u0628 \u0647\u0645\u062A\u0627 \u062A\u0639\u06CC\u06CC\u0646 \u0646\u0634\u062F\u0647", role: "admin", code: "PEER", unit: employee.unit, title: "\u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u062A\u0639\u06CC\u06CC\u0646 \u0627\u0631\u0632\u06CC\u0627\u0628 \u0647\u0645\u062A\u0627" });
    }
    case "calibration_review":
      return assigned(employee.calibrationLeadId, admin, { id: "calib-lead", name: "\u0645\u0633\u0626\u0648\u0644 \u06A9\u0627\u0644\u06CC\u0628\u0631\u0627\u0633\u06CC\u0648\u0646 \u062A\u0639\u06CC\u06CC\u0646 \u0646\u0634\u062F\u0647", role: "admin", code: "CAL-01", unit: "\u062A\u0639\u0627\u0644\u06CC \u0633\u0627\u0632\u0645\u0627\u0646\u06CC", title: "\u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u062A\u0639\u06CC\u06CC\u0646 \u0645\u0633\u0626\u0648\u0644 \u06A9\u0627\u0644\u06CC\u0628\u0631\u0627\u0633\u06CC\u0648\u0646" });
    case "hr_approval":
      return assigned(employee.approverId, admin, { id: "hr-lead", name: "\u062A\u0623\u06CC\u06CC\u062F\u06A9\u0646\u0646\u062F\u0647 HR \u062A\u0639\u06CC\u06CC\u0646 \u0646\u0634\u062F\u0647", role: "admin", code: "HR-01", unit: "\u0633\u0631\u0645\u0627\u06CC\u0647 \u0627\u0646\u0633\u0627\u0646\u06CC", title: "\u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u062A\u0639\u06CC\u06CC\u0646 \u062A\u0623\u06CC\u06CC\u062F\u06A9\u0646\u0646\u062F\u0647 HR" });
    case "hse_review":
      return assigned(employee.hseReviewerId, void 0, { id: "hse-reviewer-missing", name: "\u0628\u0627\u0632\u0628\u06CC\u0646 HSE \u062A\u0639\u06CC\u06CC\u0646 \u0646\u0634\u062F\u0647", role: "admin", code: "HSE", unit: employee.unit, title: "\u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u062A\u0639\u06CC\u06CC\u0646 \u0628\u0627\u0632\u0628\u06CC\u0646 HSE" });
    case "feedback_meeting":
      return assigned(employee.supervisorId, supervisor, { id: employee.id, name: employee.name, role: employee.role, code: employee.code, unit: employee.unit, title: "\u062C\u0644\u0633\u0647 \u0628\u0627\u0632\u062E\u0648\u0631\u062F" });
    case "rejected":
      return { id: employee.id, name: employee.name, role: employee.role, code: employee.code, unit: employee.unit, title: "\u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u0627\u0635\u0644\u0627\u062D \u0645\u0633\u062A\u0646\u062F\u0627\u062A" };
    case "appealed":
      return assigned(void 0, admin || employees[0], { id: "appeal-committee", name: "\u06A9\u0645\u06CC\u062A\u0647 \u062A\u062C\u062F\u06CC\u062F\u0646\u0638\u0631 \u062A\u0639\u06CC\u06CC\u0646 \u0646\u0634\u062F\u0647", role: "admin", code: "APPEAL", unit: "\u0645\u062F\u06CC\u0631\u06CC\u062A \u0627\u0631\u0634\u062F", title: "\u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u062A\u0639\u06CC\u06CC\u0646 \u06A9\u0645\u06CC\u062A\u0647 \u062A\u062C\u062F\u06CC\u062F\u0646\u0638\u0631" });
    case "completed":
      return { id: "completed", name: "\u0641\u0631\u0622\u06CC\u0646\u062F \u062A\u06A9\u0645\u06CC\u0644 \u0648 \u0628\u0627\u06CC\u06AF\u0627\u0646\u06CC \u0634\u062F\u0647", role: "admin", code: "DONE", unit: "\u0633\u0648\u0627\u0628\u0642 \u067E\u0631\u0633\u0646\u0644\u06CC", title: "\u0645\u062E\u062A\u0648\u0645\u0647" };
  }
}
__name(resolveWorkflowAssignee, "resolveWorkflowAssignee");

// ../src/utils/criterionScoring.ts
function manualScoreRange(criterion) {
  return { min: criterion.allowedScoreMin ?? 1, max: criterion.allowedScoreMax ?? 5 };
}
__name(manualScoreRange, "manualScoreRange");
function isManualScoreInRange(criterion, score) {
  if (score === 0) return true;
  if (!Number.isInteger(score) || score < 1 || score > 5) return false;
  const { min, max } = manualScoreRange(criterion);
  return Number.isInteger(min) && Number.isInteger(max) && min >= 1 && max <= 5 && min <= max && score >= min && score <= max;
}
__name(isManualScoreInRange, "isManualScoreInRange");
function thresholdsFollowDirection(thresholds, direction = "more") {
  const values = [thresholds.score5, thresholds.score4, thresholds.score3, thresholds.score2];
  if (values.some((value) => !Number.isFinite(value))) return false;
  return direction === "less" ? values[0] <= values[1] && values[1] <= values[2] && values[2] <= values[3] : values[0] >= values[1] && values[1] >= values[2] && values[2] >= values[3];
}
__name(thresholdsFollowDirection, "thresholdsFollowDirection");
function validManualScoreLimits(min, max) {
  if (min === void 0 && max === void 0) return true;
  const effectiveMin = min ?? 1;
  const effectiveMax = max ?? 5;
  return Number.isInteger(effectiveMin) && Number.isInteger(effectiveMax) && effectiveMin >= 1 && effectiveMin <= effectiveMax && effectiveMax <= 5;
}
__name(validManualScoreLimits, "validManualScoreLimits");

// ../src/utils/evaluationPeriod.ts
function businessDateBelongsToPeriod(date, periodId) {
  let label;
  try {
    label = normalizeDigits(periodId.startsWith("period:") ? decodeURIComponent(periodId.slice(7)) : periodId).replace(/\u200c/g, " ").trim().toLowerCase();
  } catch {
    return false;
  }
  const parsed = parseBusinessDate(date), year = label.match(/(?:^|\D)(1[34]\d{2})(?=\D|$)/);
  if (!parsed || !year) return false;
  const months = ["\u0641\u0631\u0648\u0631\u062F\u06CC\u0646", "\u0627\u0631\u062F\u06CC\u0628\u0647\u0634\u062A", "\u062E\u0631\u062F\u0627\u062F", "\u062A\u06CC\u0631", "\u0645\u0631\u062F\u0627\u062F", "\u0634\u0647\u0631\u06CC\u0648\u0631", "\u0645\u0647\u0631", "\u0622\u0628\u0627\u0646", "\u0622\u0630\u0631", "\u062F\u06CC", "\u0628\u0647\u0645\u0646", "\u0627\u0633\u0641\u0646\u062F"];
  const monthly = new RegExp("(?:^|[\\s\\d_-])(?:" + months.join("|") + ")(?:$|[\\s\\d_-])").test(label);
  const span = monthly ? 1 : /بهار|تابستان|پاییز|پائيز|زمستان|سه\s*ماهه|\bq[1-4]\b|spring|summer|autumn|fall|winter|quarter/.test(label) ? 3 : /نیمه|نيمه|\bh[12]\b|half/.test(label) ? 6 : /سالانه|سال|annual|year/.test(label) || /^1[34]\d{2}$/.test(label) ? 12 : 0;
  const start = getEvaluationPeriodStartOrdinal(label), parts = getJalaliDateParts(parsed), ordinal = parts.year * 12 + parts.month;
  return span > 0 && start !== null && ordinal >= start && ordinal < start + span;
}
__name(businessDateBelongsToPeriod, "businessDateBelongsToPeriod");
function canonicalEvaluationPeriodId(label) {
  const canonical2 = normalizeDigits(String(label || "").normalize("NFKC")).replace(/[\u200c\u200f\u0640]/g, "").replace(/[‐‑‒–—]/g, "-").trim().replace(/\s+/g, " ").toLocaleLowerCase();
  return canonical2 ? `period:${encodeURIComponent(canonical2)}` : "";
}
__name(canonicalEvaluationPeriodId, "canonicalEvaluationPeriodId");
function getEvaluationPeriodId(evaluation) {
  return evaluation.evaluationPeriodId?.trim() || canonicalEvaluationPeriodId(evaluation.period);
}
__name(getEvaluationPeriodId, "getEvaluationPeriodId");
function getEvaluationPeriodStartOrdinal(label) {
  const normalized = normalizeDigits(String(label || "").normalize("NFKC")).replace(/[\u200c\u200f\u0640]/g, "").replace(/[‐‑‒–—]/g, "-").toLocaleLowerCase();
  const yearMatch = normalized.match(/(?:^|\D)(\d{4})(?=\D|$)/);
  if (!yearMatch) return null;
  const year = Number(yearMatch[1]);
  const jalaliYear = year < 1700;
  let startMonth = 1;
  if (normalized.includes("\u0628\u0647\u0627\u0631") || /\bspring\b/.test(normalized)) startMonth = 1;
  else if (normalized.includes("\u062A\u0627\u0628\u0633\u062A\u0627\u0646") || /\bsummer\b/.test(normalized)) startMonth = 4;
  else if (normalized.includes("\u067E\u0627\u06CC\u06CC\u0632") || normalized.includes("\u067E\u0627\u0626\u064A\u0632") || /\b(?:autumn|fall)\b/.test(normalized)) startMonth = 7;
  else if (normalized.includes("\u0632\u0645\u0633\u062A\u0627\u0646") || /\bwinter\b/.test(normalized)) startMonth = 10;
  else if (/نیمه\s*دوم|نيمه\s*دوم|\bh2\b|second\s+half/.test(normalized)) startMonth = 7;
  else if (/نیمه\s*اول|نيمه\s*اول|\bh1\b|first\s+half/.test(normalized)) startMonth = 1;
  else {
    const quarterMatch = normalized.match(/(?:سه\s*ماهه\s*(اول|دوم|سوم|چهارم)|\bq([1-4])\b|quarter\s*([1-4]))/);
    if (quarterMatch) {
      const quarter = quarterMatch[1] ? ["\u0627\u0648\u0644", "\u062F\u0648\u0645", "\u0633\u0648\u0645", "\u0686\u0647\u0627\u0631\u0645"].indexOf(quarterMatch[1]) + 1 : Number(quarterMatch[2] || quarterMatch[3]);
      startMonth = (quarter - 1) * 3 + 1;
    } else {
      const jalaliMonthIndex = ["\u0641\u0631\u0648\u0631\u062F\u06CC\u0646", "\u0627\u0631\u062F\u06CC\u0628\u0647\u0634\u062A", "\u062E\u0631\u062F\u0627\u062F", "\u062A\u06CC\u0631", "\u0645\u0631\u062F\u0627\u062F", "\u0634\u0647\u0631\u06CC\u0648\u0631", "\u0645\u0647\u0631", "\u0622\u0628\u0627\u0646", "\u0622\u0630\u0631", "\u062F\u06CC", "\u0628\u0647\u0645\u0646", "\u0627\u0633\u0641\u0646\u062F"].findIndex((monthName) => normalized.includes(monthName));
      if (jalaliMonthIndex >= 0) startMonth = jalaliMonthIndex + 1;
      else if (!jalaliYear) {
        const gregorianMonth = normalized.match(/(?:^|\D)(\d{4})-(\d{1,2})(?=\D|$)/);
        if (gregorianMonth) startMonth = Number(gregorianMonth[2]);
      }
    }
  }
  if (!Number.isInteger(startMonth) || startMonth < 1 || startMonth > 12) return null;
  if (!jalaliYear) {
    if (startMonth > 12) return null;
    const jalaliStart = getJalaliDateParts(new Date(Date.UTC(year, startMonth - 1, 15, 12)));
    return jalaliStart.year * 12 + jalaliStart.month;
  }
  return year * 12 + startMonth;
}
__name(getEvaluationPeriodStartOrdinal, "getEvaluationPeriodStartOrdinal");

// ../src/utils/evaluationStart.ts
function resolveEvaluationRouteRule(employee, profileId, routeRules = DEFAULT_ROUTE_RULES) {
  const matches = routeRules.filter(
    (rule) => (!rule.unit || rule.unit === "all" || rule.unit === employee.unit) && (!rule.profileId || rule.profileId === "all" || rule.profileId === profileId)
  );
  matches.sort((left, right) => {
    const score = /* @__PURE__ */ __name((rule) => (rule.profileId && rule.profileId !== "all" ? 2 : 0) + (rule.unit && rule.unit !== "all" ? 1 : 0), "score");
    return score(right) - score(left);
  });
  return matches[0];
}
__name(resolveEvaluationRouteRule, "resolveEvaluationRouteRule");
function resolveInitialEvaluationWorkflow(employee, employees, routeRules = DEFAULT_ROUTE_RULES, profileId = employee.profileId) {
  const rule = resolveEvaluationRouteRule(employee, profileId, routeRules);
  const stage = rule?.requiresSelfReview === true ? "self_review" : "supervisor_review";
  const assignee = resolveWorkflowAssignee(stage, {
    ...employee,
    supervisorId: rule?.defaultSupervisorId || employee.supervisorId
  }, employees);
  return {
    stage,
    status: "draft",
    currentAssigneeId: assignee.id,
    currentAssigneeName: assignee.name,
    currentAssigneeRole: assignee.role,
    routeRuleId: rule?.id,
    requiresSelfReview: rule?.requiresSelfReview === true
  };
}
__name(resolveInitialEvaluationWorkflow, "resolveInitialEvaluationWorkflow");

// ../src/utils/criterionSourceRegistry.ts
function scoreConfiguredMetric(criterion, raw) {
  if (criterion.active === false || !Number.isFinite(raw)) return null;
  if (criterion.calculationType === "direct_score") return raw >= 0 && raw <= 5 ? Math.round(raw * 10) / 10 : null;
  const thresholds = criterion.scoreThresholds;
  if (!thresholds) return null;
  const ordered = [thresholds.score5, thresholds.score4, thresholds.score3, thresholds.score2];
  if (!ordered.every(Number.isFinite)) return null;
  if (criterion.dir === "less") {
    for (let index = 0; index < ordered.length; index += 1) if (raw <= ordered[index]) return 5 - index;
  } else {
    for (let index = 0; index < ordered.length; index += 1) if (raw >= ordered[index]) return 5 - index;
  }
  return 1;
}
__name(scoreConfiguredMetric, "scoreConfiguredMetric");

// ../src/utils/sourceImports.ts
function isSourceImportContext(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const context = value;
  if (typeof context.operationId !== "string" || !/^[a-zA-Z0-9:_-]{8,100}$/.test(context.operationId)) return false;
  const contextRecord = context;
  if (context.importType === "EMPLOYEE" || context.importType === "CRITERIA") return !("evaluationPeriodId" in contextRecord);
  const period = contextRecord.evaluationPeriodId;
  const validPeriod = typeof period === "string" && period.length > 0 && period.length <= 200;
  const rowsRead = contextRecord.rowsRead;
  const validSummary = rowsRead === void 0 || Number.isInteger(rowsRead) && Number(rowsRead) >= 0 && Number(rowsRead) <= 1e5;
  return (context.importType === "MIS" || context.importType === "KASRA" || context.importType === "FILE_IMPORT") && validPeriod && validSummary;
}
__name(isSourceImportContext, "isSourceImportContext");
function isProtectedSourceImportContext(value) {
  return value.importType === "MIS" || value.importType === "KASRA";
}
__name(isProtectedSourceImportContext, "isProtectedSourceImportContext");
function isMasterDataSourceImportContext(value) {
  return value.importType === "EMPLOYEE" || value.importType === "CRITERIA";
}
__name(isMasterDataSourceImportContext, "isMasterDataSourceImportContext");
function withoutKeys(value, keys) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
}
__name(withoutKeys, "withoutKeys");
function equalExcept(previous, next, allowed) {
  return JSON.stringify(withoutKeys(previous, allowed)) === JSON.stringify(withoutKeys(next, allowed));
}
__name(equalExcept, "equalExcept");
function kasraScore(criterion, raw, label) {
  switch (criterion.misMetricKey) {
    case "attendance_delay":
      return raw <= 15 ? 5 : raw <= 45 ? 4 : raw <= 120 ? 3 : raw <= 240 ? 2 : 1;
    case "attendance_absence":
      return raw === 0 ? 5 : raw <= 1 ? 3 : raw <= 2 ? 2 : 1;
    case "discipline":
      return raw === 0 ? 5 : raw === 1 ? 3 : 1;
    case "custom":
      if (criterion.customMetricField && label === `kasra_custom_metric:${criterion.id}`) return scoreConfiguredMetric(criterion, raw);
      if (label !== "kasra_composite_score") return null;
      return Math.max(0, Math.min(5, Math.round(raw * 10) / 10));
    default:
      if (label !== "kasra_composite_score") return null;
      return Math.max(0, Math.min(5, Math.round(raw * 10) / 10));
  }
}
__name(kasraScore, "kasraScore");
function misScore(criterion, raw, label) {
  switch (criterion.misMetricKey) {
    case "efficiency":
      return raw >= 104 ? 5 : raw >= 99 ? 4 : raw >= 92 ? 3 : raw >= 80 ? 2 : 1;
    case "scrap_rate":
      return raw <= 1.1 ? 5 : raw <= 2 ? 4 : raw <= 3.2 ? 3 : raw <= 5 ? 2 : 1;
    case "quality_score":
      return raw >= 98 ? 5 : raw >= 95 ? 4 : raw >= 90 ? 3 : raw >= 85 ? 2 : 1;
    case "output_qty":
      if (label !== "output_qty_ratio") return null;
      return raw >= 1.04 ? 5 : raw >= 0.98 ? 4 : raw >= 0.9 ? 3 : raw >= 0.8 ? 2 : 1;
    case "downtime":
      return raw <= 2 ? 5 : raw <= 4 ? 4 : raw <= 6 ? 3 : raw <= 9 ? 2 : 1;
    case "custom":
      if (criterion.customMetricField && label === `mis_custom_metric:${criterion.id}`) return scoreConfiguredMetric(criterion, raw);
      if (label !== "mis_composite_score") return null;
      return Math.max(0, Math.min(5, Math.round(raw * 10) / 10));
    default:
      if (label !== "mis_composite_score") return null;
      return raw >= 0 && raw <= 5 ? Math.round(raw * 10) / 10 : null;
  }
}
__name(misScore, "misScore");
function validImportedScoreChange(previous, next, criterion, importType) {
  const source = importType.toLowerCase();
  const docPrefix = importType === "KASRA" ? "\u062F\u0627\u062F\u0647 \u06A9\u0633\u0631\u06CC:" : "\u062F\u0627\u062F\u0647 \u062E\u0648\u062F\u06A9\u0627\u0631 MIS:";
  if (["not_applicable", "exempt"].includes(previous.scoreStatus || "") && next.scoreStatus !== previous.scoreStatus) return false;
  if (!criterion || criterion.active === false || criterion.scoringSource !== source || criterion.autoPopulate === false || next.sourceType !== source || next.autoPopulated !== true || typeof next.value !== "number" || !Number.isFinite(next.value) || next.value < 0 || next.value > 5 || typeof next.rawMetricValue !== "number" || !Number.isFinite(next.rawMetricValue) || next.rawMetricValue < 0 || typeof next.doc !== "string" || !next.doc.startsWith(docPrefix)) return false;
  if (!equalExcept(
    previous,
    next,
    ["value", "doc", "sourceType", "autoPopulated", "rawMetricValue", "rawMetricLabel", "scoreStatus"]
  )) return false;
  if (importType === "KASRA") {
    const expected2 = kasraScore(criterion, next.rawMetricValue, next.rawMetricLabel);
    return expected2 !== null && next.value === expected2;
  }
  const expected = importType === "MIS" ? misScore(criterion, next.rawMetricValue, next.rawMetricLabel) : null;
  return importType === "MIS" && expected !== null && next.value === expected;
}
__name(validImportedScoreChange, "validImportedScoreChange");

// ../src/utils/workflowSecurity.ts
var stageNext2 = {
  self_review: ["supervisor_review"],
  supervisor_review: ["peer_review", "calibration_review"],
  peer_review: ["calibration_review"],
  calibration_review: ["hr_approval"],
  hr_approval: ["feedback_meeting"],
  feedback_meeting: ["completed"],
  rejected: ["supervisor_review"],
  appealed: ["feedback_meeting"]
};
function isValidWorkflowEdge2(from, to, action, role) {
  if (from === "hse_review" || to === "hse_review") {
    return isValidWorkflowEdge(from, to, action, role);
  }
  if (action === "admin_override") return role === "admin";
  if (action === "reassign_assignee") return from === to;
  if (action === "reject_to_supervisor" || action === "reject_to_employee") return to === "rejected" && ["supervisor_review", "peer_review", "calibration_review", "hr_approval"].includes(from);
  if (action === "submit_appeal") return role === "employee" && ["supervisor_review", "feedback_meeting", "completed"].includes(from) && to === "appealed";
  if (action === "resolve_appeal") return from === "appealed" && to === "feedback_meeting";
  if (action === "submit_self") return role === "employee" && from === "self_review" && to === "supervisor_review";
  if (action === "submit_supervisor") return role === "employee" ? from === "rejected" && to === "supervisor_review" : (from === "supervisor_review" || from === "rejected") && ["calibration_review", "peer_review"].includes(to);
  if (action === "submit_peer") return from === "peer_review" && to === "calibration_review";
  if (action === "approve_calibration") return from === "calibration_review" && to === "hr_approval";
  if (action === "approve_hr") return from === "hr_approval" && to === "feedback_meeting";
  if (action === "complete_feedback") return from === "feedback_meeting" && to === "completed";
  if (action === "advance") return (stageNext2[from] || []).includes(to);
  return false;
}
__name(isValidWorkflowEdge2, "isValidWorkflowEdge");
function scoreSnapshot(score) {
  return JSON.stringify(score);
}
__name(scoreSnapshot, "scoreSnapshot");
function hasRequiredFinalizationInputs(evaluation) {
  return getFinalizationInputIssues(evaluation).length === 0;
}
__name(hasRequiredFinalizationInputs, "hasRequiredFinalizationInputs");
function getFinalizationInputIssues(evaluation, criteria = []) {
  if (!Array.isArray(evaluation.scores) || evaluation.scores.length === 0) return ["\u0647\u06CC\u0686 \u0645\u0639\u06CC\u0627\u0631 \u0627\u0645\u062A\u06CC\u0627\u0632\u062F\u0647\u06CC \u062F\u0631 \u067E\u0631\u0648\u0646\u062F\u0647 \u062B\u0628\u062A \u0646\u0634\u062F\u0647 \u0627\u0633\u062A."];
  const issues = [];
  for (const score of evaluation.scores) {
    const name = criteria.find((criterion) => criterion.id === score.cid || criterion.code === score.cid)?.name || score.cid;
    if (!isScoreDispositionComplete(score)) {
      issues.push(`\u0628\u0631\u0627\u06CC \u0645\u0639\u06CC\u0627\u0631 \xAB${name}\xBB \u0627\u0645\u062A\u06CC\u0627\u0632 \u06CC\u0627 \u0648\u0636\u0639\u06CC\u062A \xAB\u0646\u06CC\u0627\u0632 \u0628\u0647 \u0627\u0645\u062A\u06CC\u0627\u0632 \u0646\u062F\u0627\u0631\u062F\xBB \u062B\u0628\u062A \u0646\u0634\u062F\u0647 \u0627\u0633\u062A.`);
      continue;
    }
    if (isNumericScoreRecorded(score) && NEED_DOCUMENT_SCORES.includes(score.value) && !(score.doc?.trim() && score.doc.trim().length >= 5)) {
      issues.push(`\u0628\u0631\u0627\u06CC \u0645\u0639\u06CC\u0627\u0631 \xAB${name}\xBB \u0628\u0627 \u0627\u0645\u062A\u06CC\u0627\u0632 ${score.value}\u060C \u0645\u0633\u062A\u0646\u062F \u067E\u0634\u062A\u06CC\u0628\u0627\u0646 \u062D\u062F\u0627\u0642\u0644 \u06F5 \u0646\u0648\u06CC\u0633\u0647\u200C\u0627\u06CC \u0644\u0627\u0632\u0645 \u0627\u0633\u062A.`);
    }
  }
  return issues;
}
__name(getFinalizationInputIssues, "getFinalizationInputIssues");
function withoutSupervisorInput(breakdown) {
  if (!breakdown) return void 0;
  const { supervisorScore: _supervisorScore, ...sourceOwnedValues } = breakdown;
  return Object.keys(sourceOwnedValues).length ? sourceOwnedValues : void 0;
}
__name(withoutSupervisorInput, "withoutSupervisorInput");
function equalExcept2(record, other, ignored) {
  const omit = /* @__PURE__ */ __name((value) => Object.fromEntries(Object.entries(value).filter(([key]) => !ignored.includes(key))), "omit");
  return JSON.stringify(omit(record)) === JSON.stringify(omit(other));
}
__name(equalExcept2, "equalExcept");
function multiSourceWriteAllowed(oldScore, next, criterion) {
  const acceptsSupervisorInput = criterion?.multiSourceConfig?.items.some((item) => item.source === "supervisor") === true;
  if (!acceptsSupervisorInput || !criterion || !next.sourceBreakdown || JSON.stringify(withoutSupervisorInput(oldScore.sourceBreakdown)) !== JSON.stringify(withoutSupervisorInput(next.sourceBreakdown)) || !equalExcept2(oldScore, next, ["value", "doc", "sourceBreakdown", "scoreStatus"])) return "mis_value_read_only";
  const oldSupervisorInput = oldScore.sourceBreakdown?.supervisorScore;
  const newSupervisorInput = next.sourceBreakdown.supervisorScore;
  if (newSupervisorInput !== void 0 && (!Number.isFinite(newSupervisorInput) || newSupervisorInput < 1 || newSupervisorInput > 5)) return "score_field_denied";
  const inputChanged = oldSupervisorInput !== newSupervisorInput;
  if (!inputChanged && next.value !== oldScore.value) return "mis_value_read_only";
  if (inputChanged) {
    const composite = calculateMultiSourceCompositeScore(criterion, next.sourceBreakdown);
    if (next.value !== composite.score || next.doc !== oldScore.doc && next.doc !== composite.docText) return "score_field_denied";
  }
  return null;
}
__name(multiSourceWriteAllowed, "multiSourceWriteAllowed");
function adminMISImportAllowed(oldScore, next, criterion) {
  if (["not_applicable", "exempt"].includes(oldScore.scoreStatus || "") && next.scoreStatus !== oldScore.scoreStatus) return false;
  if (criterion?.scoringSource !== "mis" || criterion.autoPopulate === false || next.sourceType !== "mis" || next.autoPopulated !== true || !Number.isFinite(next.value) || next.value < 0 || next.value > 5 || typeof next.rawMetricValue !== "number" || !Number.isFinite(next.rawMetricValue) || next.rawMetricValue < 0 || !next.doc?.startsWith("\u062F\u0627\u062F\u0647 \u062E\u0648\u062F\u06A9\u0627\u0631 MIS:")) return false;
  return equalExcept2(
    oldScore,
    next,
    ["value", "doc", "sourceType", "autoPopulated", "rawMetricValue", "scoreStatus"]
  );
}
__name(adminMISImportAllowed, "adminMISImportAllowed");
function scoreWriteAllowed(existing, incoming, actor, criteria, sourceImport) {
  const oldByCid = new Map(existing.scores.map((score) => [score.cid, score]));
  const newByCid = new Map(incoming.scores.map((score) => [score.cid, score]));
  if (oldByCid.size !== newByCid.size || [...oldByCid.keys()].some((cid) => !newByCid.has(cid))) return "score_field_denied";
  const stage = existing.stage || "self_review";
  for (const [cid, oldScore] of oldByCid) {
    const next = newByCid.get(cid);
    if (scoreSnapshot(oldScore) === scoreSnapshot(next)) continue;
    const criterion = criteria.find((item) => item.id === cid);
    if (criterion?.active === false && (next.value !== oldScore.value || next.self !== oldScore.self || JSON.stringify(next.sourceBreakdown) !== JSON.stringify(oldScore.sourceBreakdown))) return "permission_denied";
    const multiSource = criterion?.scoringSource !== void 0 ? criterion.scoringSource === "multi_source" : oldScore.sourceType === "multi_source";
    const sourceOwned = criterion?.scoringSource !== void 0 ? ["mis", "kasra", "system"].includes(criterion.scoringSource) || criterion.scoringSource === "multi_source" && !criterion.multiSourceConfig?.items.some((item) => item.source === "supervisor") : oldScore.autoPopulated || ["mis", "kasra", "system", "auto"].includes(oldScore.sourceType || "");
    if (next.scoreStatus !== oldScore.scoreStatus && ["pending", "not_applicable", "exempt"].includes(next.scoreStatus || "") && equalExcept2(oldScore, next, ["scoreStatus"])) {
      if (next.scoreStatus === "exempt" && actor.role !== "admin") return "permission_denied";
      if (actor.role === "admin") continue;
      if (actor.role === "supervisor" && stage === "supervisor_review" && !sourceOwned) continue;
      return actor.role === "supervisor" ? "score_stage_denied" : "score_field_denied";
    }
    if ((criterion?.scoringSource === "supervisor" || !criterion?.scoringSource && oldScore.sourceType === "supervisor") && next.value !== oldScore.value && !isManualScoreInRange(criterion || {}, next.value)) return "score_limit_exceeded";
    if (multiSource && criterion?.multiSourceConfig?.items.some((item) => item.source === "supervisor") && next.sourceBreakdown?.supervisorScore !== oldScore.sourceBreakdown?.supervisorScore && !isManualScoreInRange(criterion, next.sourceBreakdown?.supervisorScore ?? 0)) return "score_limit_exceeded";
    if (sourceOwned && !multiSource) {
      const employeeSelfScoreAllowed = actor.role === "employee" && ["self_review", "rejected"].includes(stage) && Number.isInteger(next.self) && next.self >= 0 && next.self <= 5 && equalExcept2(oldScore, next, ["self", "selfScoreStatus"]);
      if (employeeSelfScoreAllowed) continue;
      if (sourceImport) {
        if (sourceImport.importType.toLowerCase() !== criterion?.scoringSource || !validImportedScoreChange(oldScore, next, criterion, sourceImport.importType)) return "source_import_invalid";
        continue;
      }
      if (actor.role !== "admin" || !adminMISImportAllowed(oldScore, next, criterion)) return "mis_value_read_only";
      continue;
    }
    if (actor.role === "supervisor") {
      if (stage !== "supervisor_review") return "score_stage_denied";
      if (multiSource) {
        const failure = multiSourceWriteAllowed(oldScore, next, criterion);
        if (failure) return failure;
        continue;
      }
      if (next.sourceType !== oldScore.sourceType || next.autoPopulated === true !== (oldScore.autoPopulated === true) || !equalExcept2(oldScore, next, ["value", "doc", "scoreStatus", "autoPopulated"])) return "score_field_denied";
    } else if (actor.role === "employee") {
      if (stage !== "self_review" && stage !== "rejected") return "score_stage_denied";
      if (next.value !== oldScore.value || !equalExcept2(oldScore, next, ["self", "selfScoreStatus", "doc"])) return "score_field_denied";
    } else {
      if (multiSource) {
        const failure = multiSourceWriteAllowed(oldScore, next, criterion);
        if (failure) return failure;
        continue;
      }
      if (next.sourceType !== oldScore.sourceType && oldScore.sourceType && oldScore.sourceType !== "supervisor") return "mis_value_read_only";
    }
  }
  return null;
}
__name(scoreWriteAllowed, "scoreWriteAllowed");
function validateSourceImportEvaluation(existing, incoming, context) {
  const sourceImport = context.sourceImport;
  if (!sourceImport) return null;
  const importType = sourceImport.importType.toLowerCase();
  const employee = context.employees.find((item) => item.id === existing.empId);
  if (!employee || !canImport(context.actor, importType, employee, context.permissionPolicy).allowed) {
    return sourceImport.importType === "KASRA" ? "kasra_import_not_authorized" : "mis_import_not_authorized";
  }
  if (getEvaluationPeriodId(existing) !== sourceImport.evaluationPeriodId || getEvaluationPeriodId(incoming) !== sourceImport.evaluationPeriodId || existing.status === "locked" || existing.stage === "completed" || !equalExcept2(existing, incoming, ["scores"]) || JSON.stringify(existing.scores) === JSON.stringify(incoming.scores)) return "source_import_invalid";
  const profile = context.profiles?.find((item) => item.id === existing.profileId);
  if (!profile) return "source_import_invalid";
  const criteriaById = /* @__PURE__ */ new Map();
  (context.criteria || []).forEach((item) => {
    criteriaById.set(item.id, item);
    criteriaById.set(item.code, item);
  });
  const profileCriterionIds = new Set(profile.items.flatMap((item) => {
    const criterion = criteriaById.get(item.cid);
    return criterion ? [item.cid, criterion.id, criterion.code] : [item.cid];
  }));
  const previousScores = new Map(existing.scores.map((item) => [item.cid, item]));
  const nextScores = new Map(incoming.scores.map((item) => [item.cid, item]));
  for (const [cid, previous] of previousScores) {
    const next = nextScores.get(cid);
    if (!next) return "source_import_invalid";
    if (JSON.stringify(previous) === JSON.stringify(next)) continue;
    if (!profileCriterionIds.has(cid) || !validImportedScoreChange(previous, next, criteriaById.get(cid), sourceImport.importType)) return "source_import_invalid";
  }
  if (nextScores.size !== previousScores.size) return "source_import_invalid";
  return null;
}
__name(validateSourceImportEvaluation, "validateSourceImportEvaluation");
function isValidCompletedAppealSubmission(existing, incoming, actor) {
  const log = incoming.history?.[0];
  const appeal = incoming.appeal;
  if (actor.role !== "employee" || existing.empId !== actor.id || existing.stage !== "completed" || existing.status !== "locked" || incoming.stage !== "appealed" || incoming.status !== "draft" || log?.action !== "submit_appeal" || log.fromStage !== "completed" || log.toStage !== "appealed" || !appeal || appeal.status !== "submitted" || appeal.id === existing.appeal?.id || appeal.evalId !== existing.id || appeal.empId !== actor.id || appeal.period !== existing.period || !appeal.reason?.trim() || existing.appeal?.status === "submitted") return false;
  return equalExcept2(
    existing,
    incoming,
    ["stage", "status", "currentAssigneeId", "currentAssigneeName", "currentAssigneeRole", "history", "appeal", "rejectionReason"]
  );
}
__name(isValidCompletedAppealSubmission, "isValidCompletedAppealSubmission");
function validateEvaluationWrite(existing, incoming, context) {
  const { actor, employees, delegations, permissionPolicy } = context;
  if (!incoming?.id || !incoming.empId || existing && (existing.empId !== incoming.empId || existing.id !== incoming.id)) return "identity_changed";
  if (!existing) {
    if (actor.role !== "admin") return "new_evaluation_requires_admin";
    if (incoming.scores.some((s) => context.criteria?.some((c) => (c.id === s.cid || c.code === s.cid) && c.active === false) && (s.value > 0 || s.self > 0))) return "permission_denied";
    if (incoming.retiredScores?.length) return "score_field_denied";
    const employee = employees.find((item) => item.id === incoming.empId);
    if (!employee) return "identity_changed";
    const initial = resolveInitialEvaluationWorkflow(employee, employees, context.routeRules || DEFAULT_ROUTE_RULES, incoming.profileId);
    if (incoming.stage !== initial.stage || incoming.currentAssigneeId !== initial.currentAssigneeId || incoming.currentAssigneeName !== initial.currentAssigneeName || incoming.currentAssigneeRole !== initial.currentAssigneeRole || incoming.requiresSelfReview !== initial.requiresSelfReview || incoming.routeRuleId && incoming.routeRuleId !== initial.routeRuleId) return "invalid_transition";
    return null;
  }
  if (JSON.stringify(existing) === JSON.stringify(incoming)) return null;
  if (JSON.stringify(existing.retiredScores || []) !== JSON.stringify(incoming.retiredScores || [])) return "score_field_denied";
  const completedAppealSubmission = isValidCompletedAppealSubmission(existing, incoming, actor);
  if ((existing.stage === "completed" || existing.status === "locked") && JSON.stringify(existing) !== JSON.stringify(incoming) && !completedAppealSubmission) return "completed_immutable";
  if (context.sourceImport) {
    const importFailure = validateSourceImportEvaluation(existing, incoming, context);
    if (importFailure) return importFailure;
    return scoreWriteAllowed(existing, incoming, actor, context.criteria || [], context.sourceImport);
  }
  const oldHistory = existing.history || [];
  const nextHistory = incoming.history || [];
  const newest = nextHistory[0];
  const historyUnchanged = JSON.stringify(oldHistory) === JSON.stringify(nextHistory);
  const stageChanged = (existing.stage || "self_review") !== (incoming.stage || "self_review");
  const ownerChanged = existing.currentAssigneeId !== incoming.currentAssigneeId;
  if (!historyUnchanged) {
    if (nextHistory.length !== oldHistory.length + 1 || !newest || JSON.stringify(nextHistory.slice(1)) !== JSON.stringify(oldHistory)) return "history_rewritten";
    const from = existing.stage || "self_review";
    const to = incoming.stage || "self_review";
    if (newest.fromStage !== from || newest.toStage !== to || !isValidWorkflowEdge2(from, to, newest.action, actor.role)) return "invalid_transition";
    const hseRoute = newest.action === "route_hse";
    const hseComplete = newest.action === "complete_hse_review";
    if (hseRoute || hseComplete) {
      const employee = employees.find((item) => item.id === existing.empId);
      const context2 = incoming.hseReviewContext;
      const reviewer = employee?.hseReviewerId ? employees.find((item) => item.id === employee.hseReviewerId) : void 0;
      const allowedReturnStages = HSE_RETURNABLE_STAGES;
      if (!employee || existing.status === "locked" || existing.stage === "completed") return "completed_immutable";
      if (!equalExcept2(
        existing,
        incoming,
        ["stage", "status", "currentAssigneeId", "currentAssigneeName", "currentAssigneeRole", "history", "hseReviewContext"]
      )) return "invalid_transition";
      if (hseRoute) {
        if (!allowedReturnStages.includes(from) || to !== "hse_review" || !reviewer || context2?.requestedFromStage !== from || context2.returnStage !== from || context2.requestedById !== actor.id || !context2.reason?.trim() || context2.hseReviewerId !== reviewer.id || context2.returnAssigneeId !== existing.currentAssigneeId || context2.returnAssigneeName !== existing.currentAssigneeName || context2.returnAssigneeRole !== existing.currentAssigneeRole || incoming.currentAssigneeId !== reviewer.id || incoming.currentAssigneeName !== reviewer.name || incoming.currentAssigneeRole !== reviewer.role || incoming.status !== existing.status) return "invalid_transition";
        if (actor.role !== "admin") {
          const auth = canPerformWorkflowAction(actor, existing, "route_hse", { employees, delegations, permissionPolicy });
          if (!auth.authorized) return "permission_denied";
        }
      } else {
        const prior = existing.hseReviewContext;
        if (from !== "hse_review" || !prior || actor.id !== prior.hseReviewerId || existing.currentAssigneeId !== actor.id || to !== prior.returnStage || !allowedReturnStages.includes(prior.returnStage) || context2?.requestedAt !== prior.requestedAt || context2.requestedById !== prior.requestedById || context2.hseReviewerId !== prior.hseReviewerId || context2.returnStage !== prior.returnStage || context2.returnAssigneeId !== prior.returnAssigneeId || context2.returnAssigneeName !== prior.returnAssigneeName || context2.returnAssigneeRole !== prior.returnAssigneeRole || !context2.reviewedAt || incoming.currentAssigneeId !== prior.returnAssigneeId || incoming.currentAssigneeName !== prior.returnAssigneeName || incoming.currentAssigneeRole !== prior.returnAssigneeRole || incoming.status !== existing.status) return "permission_denied";
        const auth = canPerformWorkflowAction(actor, existing, "complete_hse_review", { employees, delegations, permissionPolicy });
        if (!auth.authorized) return "permission_denied";
      }
    }
    if (newest.action !== "reassign_assignee" && !hseRoute && !hseComplete) {
      const expectedOwner = resolveWorkflowAssignee(to, employees.find((item) => item.id === incoming.empId), employees);
      if (incoming.currentAssigneeId !== expectedOwner.id || incoming.currentAssigneeName !== expectedOwner.name || incoming.currentAssigneeRole !== expectedOwner.role) return "owner_change_requires_reassignment";
    }
    if (newest.action === "reassign_assignee") {
      const newOwner = employees.find((item) => item.id === incoming.currentAssigneeId);
      if (!newOwner || incoming.currentAssigneeName !== newOwner.name || incoming.currentAssigneeRole !== newOwner.role) return "owner_change_requires_reassignment";
      if (actor.role === "supervisor" && !isWithinSupervisorScope(actor, newOwner, employees)) return "permission_denied";
    }
    if (newest.actorId !== actor.id) return "permission_denied";
    if (newest.action === "reassign_assignee" && !ownerChanged) return "invalid_transition";
    if (newest.action !== "reassign_assignee" && !stageChanged && newest.action !== "admin_override") return "invalid_transition";
    if (actor.role !== "admin" && !hseRoute && !hseComplete) {
      const actionName = newest.action === "reject_to_employee" || newest.action === "reject_to_supervisor" ? "reject" : newest.action === "reassign_assignee" ? "reassign" : newest.action === "submit_appeal" ? "appeal" : newest.action === "complete_feedback" ? "finalize" : newest.action === "submit_supervisor" && from === "rejected" ? "advance" : ["submit_supervisor", "submit_peer", "approve_calibration", "approve_hr", "resolve_appeal"].includes(newest.action) ? "approve" : "advance";
      const currentEval = { ...existing, history: oldHistory };
      const check = canPerformWorkflowAction(actor, currentEval, actionName, { employees, delegations, permissionPolicy });
      if (!check.authorized) return "permission_denied";
      if (actor.role === "supervisor" && !isWithinWorkflowCeiling(actor, to, permissionPolicy)) return "ceiling_exceeded";
      if (["submit_self", "submit_supervisor", "submit_peer", "approve_calibration", "approve_hr", "complete_feedback", "resolve_appeal", "advance"].includes(newest.action) && !canAccessWorkflowStage(actor, from, actionName === "advance" ? "advance" : "act", permissionPolicy)) return "ceiling_exceeded";
    }
  } else if (stageChanged) return "transition_missing_history";
  else if (ownerChanged) return "owner_change_requires_reassignment";
  const scoreFailure = scoreWriteAllowed(existing, incoming, actor, context.criteria || []);
  if (scoreFailure) return scoreFailure;
  if (incoming.stage === "completed" && incoming.status !== "locked") return "invalid_transition";
  if (incoming.status === "locked" && incoming.stage !== "completed") return "invalid_transition";
  if (incoming.stage === "completed" && !hasRequiredFinalizationInputs(incoming)) return "missing_required_input";
  if (incoming.status === "locked" && existing.status !== "locked" && (historyUnchanged || !["complete_feedback", "admin_override"].includes(newest?.action || ""))) return "permission_denied";
  if (!historyUnchanged && newest?.action !== "reassign_assignee" && actor.role !== "admin" && !stageChanged) return "invalid_transition";
  if (actor.role !== "admin" && !stageChanged && !ownerChanged) {
    const emp = employees.find((item) => item.id === existing.empId);
    const canEdit = emp && (actor.role === "employee" ? actor.id === emp.id && ["self_review", "rejected"].includes(existing.stage || "self_review") : authorize(actor, "evaluations", "edit", isExplicitlyReassigned(existing) && existing.currentAssigneeId === actor.id ? void 0 : emp, permissionPolicy).allowed && canAccessWorkflowStage(actor, existing.stage || "self_review", "edit", permissionPolicy) && existing.stage === "supervisor_review" && canPerformWorkflowAction(actor, existing, "approve", { employees, delegations, permissionPolicy }).authorized);
    if (!canEdit) return "permission_denied";
  }
  return null;
}
__name(validateEvaluationWrite, "validateEvaluationWrite");

// ../src/utils/employeeDeletion.ts
var employeeRelationshipFields = [
  "supervisorId",
  "peerReviewerId",
  "calibrationLeadId",
  "approverId",
  "hrPartnerId"
];
function getEmployeeDeletionBlockReason(target, remainingEmployees, evaluations, archivedEvaluations) {
  if (target.role === "admin" || target.username?.toLowerCase() === "admin" && target.code === "ADMIN-001") return "protected_admin";
  if (evaluations.some((item) => item.empId === target.id) || archivedEvaluations.some((item) => item.empId === target.id)) return "evaluation_history";
  if (evaluations.some((item) => item.currentAssigneeId === target.id && item.stage !== "completed" && item.status !== "locked")) return "open_workflow_task";
  if (remainingEmployees.some((employee) => employee.id !== target.id && employeeRelationshipFields.some((field) => employee[field] === target.id))) return "employee_relationship";
  return null;
}
__name(getEmployeeDeletionBlockReason, "getEmployeeDeletionBlockReason");

// ../src/utils/evaluationCriteria.ts
function getEvaluationCriteriaConfigurationSnapshot(evaluation, profiles, criteria) {
  if (evaluation.status === "locked" || evaluation.stage === "completed") return null;
  const profile = profiles.find((item) => item.id === evaluation.profileId);
  const criteriaById = new Map(criteria.map((criterion) => [criterion.id, criterion]));
  return {
    profile: profile ? {
      id: profile.id,
      title: profile.title,
      code: profile.code,
      family: profile.family,
      items: profile.items.map((item) => ({ cid: item.cid, weight: item.weight }))
    } : null,
    criteria: (profile?.items || []).map((item) => {
      const criterion = criteriaById.get(item.cid);
      if (!criterion) return null;
      return {
        id: criterion.id,
        code: criterion.code,
        name: criterion.name,
        def: criterion.def,
        source: criterion.source,
        method: criterion.method,
        dir: criterion.dir,
        scoringSource: criterion.scoringSource,
        misMetricKey: criterion.misMetricKey,
        customMetricField: criterion.customMetricField,
        autoPopulate: criterion.autoPopulate,
        misTargetValue: criterion.misTargetValue,
        unit: criterion.unit,
        targetValue: criterion.targetValue,
        scoreThresholds: criterion.scoreThresholds,
        allowedScoreMin: criterion.allowedScoreMin,
        allowedScoreMax: criterion.allowedScoreMax,
        required: criterion.required,
        active: criterion.active,
        dataType: criterion.dataType,
        aggregation: criterion.aggregation,
        calculationType: criterion.calculationType,
        formulaExpression: criterion.formulaExpression,
        variables: criterion.variables,
        sourceOwnership: criterion.sourceOwnership
      };
    })
  };
}
__name(getEvaluationCriteriaConfigurationSnapshot, "getEvaluationCriteriaConfigurationSnapshot");
function reconcileEvaluationCriteria(evaluation, profile, criteria) {
  if (!profile || evaluation.status === "locked" || evaluation.stage === "completed") return evaluation;
  const criteriaById = new Map(criteria.map((criterion) => [criterion.id, criterion]));
  const activeProfileItems = profile.items.filter(
    (item, index, items) => items.findIndex((candidate) => candidate.cid === item.cid) === index && criteriaById.get(item.cid)?.active !== false
  );
  const profileCriterionIds = new Set(activeProfileItems.map((item) => item.cid));
  const currentScores = new Map(evaluation.scores.map((score) => [score.cid, score]));
  const retiredScores = new Map((evaluation.retiredScores || []).map((score) => [score.cid, score]));
  for (const score of evaluation.scores) {
    if (!profileCriterionIds.has(score.cid)) retiredScores.set(score.cid, score);
  }
  const refreshedSlots = activeProfileItems.map((item) => {
    const existing = currentScores.get(item.cid) || retiredScores.get(item.cid);
    if (!existing) return { cid: item.cid, weight: item.weight, value: 0, self: 0 };
    const criterion = criteriaById.get(item.cid);
    const configuredSource = criterion?.scoringSource;
    const priorSource = existing.sourceType || "supervisor";
    const sourceChanged = configuredSource !== void 0 && (priorSource !== configuredSource || configuredSource === "supervisor" && existing.autoPopulated === true);
    const hasRecordedScore = existing.scoreStatus === "scored" || existing.scoreStatus === void 0 && existing.value > 0;
    const needsReview = sourceChanged && hasRecordedScore;
    const sourceMigration = configuredSource === "supervisor" && sourceChanged ? { sourceType: "supervisor", autoPopulated: false } : {};
    const reconciled = {
      ...existing,
      weight: item.weight,
      ...sourceMigration,
      ...needsReview ? { scoreStatus: "pending" } : {}
    };
    return JSON.stringify(reconciled) === JSON.stringify(existing) ? existing : reconciled;
  });
  const scores = refreshedSlots;
  const nextRetiredScores = [...retiredScores.values()].filter((score) => !profileCriterionIds.has(score.cid));
  const nextRetiredValue = nextRetiredScores.length ? nextRetiredScores : void 0;
  if (JSON.stringify(scores) === JSON.stringify(evaluation.scores) && JSON.stringify(nextRetiredScores) === JSON.stringify(evaluation.retiredScores || [])) return evaluation;
  return { ...evaluation, scores, retiredScores: nextRetiredValue };
}
__name(reconcileEvaluationCriteria, "reconcileEvaluationCriteria");
function reconcileActiveEvaluations(evaluations, profiles, criteria) {
  const profilesById = new Map(profiles.map((profile) => [profile.id, profile]));
  return evaluations.map((evaluation) => reconcileEvaluationCriteria(
    evaluation,
    profilesById.get(evaluation.profileId),
    criteria
  ));
}
__name(reconcileActiveEvaluations, "reconcileActiveEvaluations");

// ../src/utils/workflowSla.ts
var WORKFLOW_SLA_STAGES = [
  { key: "self_review", label: "\u062E\u0648\u062F\u0627\u0631\u0632\u06CC\u0627\u0628\u06CC" },
  { key: "supervisor_review", label: "\u0627\u0631\u0632\u06CC\u0627\u0628\u06CC \u0633\u0631\u067E\u0631\u0633\u062A" },
  { key: "peer_review", label: "\u0628\u0627\u0632\u062E\u0648\u0631\u062F \u0647\u0645\u062A\u0627" },
  { key: "calibration_review", label: "\u06A9\u0627\u0644\u06CC\u0628\u0631\u0627\u0633\u06CC\u0648\u0646" },
  { key: "hr_approval", label: "\u062A\u0623\u06CC\u06CC\u062F \u0645\u0646\u0627\u0628\u0639 \u0627\u0646\u0633\u0627\u0646\u06CC" },
  { key: "feedback_meeting", label: "\u062C\u0644\u0633\u0647 \u0628\u0627\u0632\u062E\u0648\u0631\u062F" },
  { key: "hse_review", label: "\u0628\u0631\u0631\u0633\u06CC HSE", optional: true },
  { key: "rejected", label: "\u0627\u0635\u0644\u0627\u062D \u067E\u0631\u0648\u0646\u062F\u0647" },
  { key: "appealed", label: "\u0631\u0633\u06CC\u062F\u06AF\u06CC \u0628\u0647 \u0627\u0639\u062A\u0631\u0627\u0636" }
];
var ALLOWED_STAGE_KEYS = new Set(WORKFLOW_SLA_STAGES.map((stage) => stage.key));
var DAY_MS = 24 * 60 * 60 * 1e3;
function isValidWorkflowSlaConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value).every(
    ([stage, days]) => ALLOWED_STAGE_KEYS.has(stage) && Number.isInteger(days) && Number(days) >= 0 && Number(days) <= 365
  );
}
__name(isValidWorkflowSlaConfig, "isValidWorkflowSlaConfig");

// ../src/utils/disciplinaryViolations.ts
var EMPTY_VIOLATION_POLICY = {
  version: "draft",
  active: false,
  approvalReference: "",
  effectiveFrom: "",
  effectiveUntil: "",
  maximumDeduction: 0,
  categories: []
};
var ViolationError = class extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
  static {
    __name(this, "ViolationError");
  }
};
var text = /* @__PURE__ */ __name((v, max = 1e3) => typeof v === "string" && v.trim().length > 0 && v.length <= max, "text");
function validViolationPolicy(value) {
  const p = value;
  if (!p || !text(p.version, 100) || typeof p.active !== "boolean" || !Number.isFinite(p.maximumDeduction) || p.maximumDeduction < 0 || p.maximumDeduction > 100 || !Array.isArray(p.categories) || p.categories.length > 100) return false;
  if (p.active && (!text(p.approvalReference) || !parseBusinessDate(p.effectiveFrom) || !parseBusinessDate(p.effectiveUntil) || parseBusinessDate(p.effectiveFrom) > parseBusinessDate(p.effectiveUntil))) return false;
  return new Set(p.categories.map((c) => c.id)).size === p.categories.length && p.categories.every((c) => text(c.id, 100) && text(c.title, 200) && typeof c.attendanceRelated === "boolean" && c.points && Object.keys(c.points).length > 0 && Object.entries(c.points).every(([key, n]) => text(key, 100) && Number.isFinite(n) && n >= 0 && n <= p.maximumDeduction));
}
__name(validViolationPolicy, "validViolationPolicy");
function incidentKey(v) {
  return [v.employeeId, v.periodId, v.date, v.categoryId, v.evidence.trim()].join("\0");
}
__name(incidentKey, "incidentKey");
function applyViolationCommands(args) {
  if (!Array.isArray(args.commands) || args.commands.length < 1 || args.commands.length > 250) throw new ViolationError("\u0647\u0631 \u0639\u0645\u0644\u06CC\u0627\u062A \u0628\u0627\u06CC\u062F \u0634\u0627\u0645\u0644 \u06F1 \u062A\u0627 \u06F2\u06F5\u06F0 \u0627\u0642\u062F\u0627\u0645 \u062A\u062E\u0644\u0641 \u0628\u0627\u0634\u062F.");
  const byId = new Map(args.records.map((r) => [r.id, r]));
  const incidents = new Set(args.records.map(incidentKey));
  const external = new Set(args.records.filter((r) => r.externalId).map((r) => `${r.source}:${r.externalId}`));
  const employees = new Map(args.employees.map((e) => [e.id, e]));
  const evaluations = new Map(args.evaluations.map((e) => [`${e.empId}\0${getEvaluationPeriodId(e)}`, e]));
  const affected = /* @__PURE__ */ new Set();
  const audit = [];
  for (const command of args.commands) {
    if (!command || typeof command !== "object") throw new ViolationError("\u0627\u0642\u062F\u0627\u0645 \u062A\u062E\u0644\u0641 \u0645\u0639\u062A\u0628\u0631 \u0646\u06CC\u0633\u062A.");
    const incoming = command.action === "create" ? command.record : void 0;
    const old = incoming ? void 0 : byId.get("id" in command ? command.id : "");
    const employee = employees.get(incoming?.employeeId || old?.employeeId || "");
    if (!employee) throw new ViolationError("\u06A9\u0627\u0631\u0645\u0646\u062F \u062A\u062E\u0644\u0641 \u067E\u06CC\u062F\u0627 \u0646\u0634\u062F.");
    const capability = command.action === "create" ? incoming?.source === "excel" ? "import" : "create" : ["approve", "reject", "reverse"].includes(command.action) ? "approve" : command.action === "review" ? "edit" : "submit";
    const ownAppeal = command.action === "appeal" && employee.id === args.actor.id;
    if (!ownAppeal && !authorize(args.actor, "violations", capability, employee, args.permissions).allowed) throw new ViolationError("\u0645\u062C\u0648\u0632 \u0627\u0642\u062F\u0627\u0645 \u0628\u0631 \u0627\u06CC\u0646 \u062A\u062E\u0644\u0641 \u0631\u0627 \u0646\u062F\u0627\u0631\u06CC\u062F.", 403);
    let next;
    if (incoming) {
      if (!text(incoming.id, 100) || !text(incoming.periodId, 200) || !parseBusinessDate(incoming.date) || !text(incoming.categoryId, 100) || !text(incoming.severity, 100) || !text(incoming.evidence) || !text(incoming.description) || !["manual", "excel"].includes(incoming.source) || incoming.externalId !== void 0 && !text(incoming.externalId, 150)) throw new ViolationError("\u0634\u0646\u0627\u0633\u0647\u060C \u062A\u0627\u0631\u06CC\u062E\u060C \u062F\u0648\u0631\u0647\u060C \u062F\u0633\u062A\u0647\u060C \u0634\u062F\u062A\u060C \u0634\u0631\u062D \u0648 \u0645\u062F\u0631\u06A9 \u0645\u0639\u062A\u0628\u0631 \u0627\u0644\u0632\u0627\u0645\u06CC \u0627\u0633\u062A.");
      if (!args.policy.categories.some((c) => c.id === incoming.categoryId && Object.hasOwn(c.points, incoming.severity))) throw new ViolationError("\u062F\u0633\u062A\u0647 \u06CC\u0627 \u0634\u062F\u062A \u062F\u0631 \u0633\u06CC\u0627\u0633\u062A \u062B\u0628\u062A \u0646\u0634\u062F\u0647 \u0627\u0633\u062A.");
      if (!businessDateBelongsToPeriod(incoming.date, incoming.periodId)) throw new ViolationError("\u062A\u0627\u0631\u06CC\u062E \u062A\u062E\u0644\u0641 \u062F\u0627\u062E\u0644 \u062F\u0648\u0631\u0647 \u0627\u0631\u0632\u06CC\u0627\u0628\u06CC \u0642\u0627\u0628\u0644 \u062A\u0634\u062E\u06CC\u0635 \u0646\u06CC\u0633\u062A\u061B \u062F\u0648\u0631\u0647 \u0648 \u062A\u0627\u0631\u06CC\u062E \u0631\u0627 \u0628\u0631\u0631\u0633\u06CC \u06A9\u0646\u06CC\u062F.");
      next = { id: incoming.id, employeeId: employee.id, periodId: incoming.periodId, date: getJalaliDateKey(parseBusinessDate(incoming.date)), categoryId: incoming.categoryId, severity: incoming.severity, evidence: incoming.evidence.trim(), description: incoming.description.trim(), source: incoming.source, ...incoming.externalId ? { externalId: incoming.externalId } : {}, status: "draft", reporterId: args.actor.id, points: 0, history: [] };
      if (byId.has(next.id) || incidents.has(incidentKey(next)) || next.externalId && external.has(`${next.source}:${next.externalId}`)) throw new ViolationError("\u062A\u062E\u0644\u0641 \u062A\u06A9\u0631\u0627\u0631\u06CC \u0627\u0633\u062A\u061B \u0647\u06CC\u0686 \u062F\u0627\u062F\u0647\u200C\u0627\u06CC \u062F\u0648\u0628\u0627\u0631\u0647 \u062B\u0628\u062A \u0646\u0634\u062F.", 409);
      incidents.add(incidentKey(next));
      if (next.externalId) external.add(`${next.source}:${next.externalId}`);
    } else {
      if (!old || !("reason" in command) || !text(command.reason)) throw new ViolationError("\u062A\u062E\u0644\u0641 \u0648 \u062F\u0644\u06CC\u0644 \u0627\u0642\u062F\u0627\u0645 \u0645\u0639\u062A\u0628\u0631 \u0627\u0644\u0632\u0627\u0645\u06CC \u0627\u0633\u062A.");
      const transitions = { submit: ["draft"], review: ["submitted"], approve: ["review"], reject: ["submitted", "review"], appeal: ["approved"], reverse: ["approved", "appealed"] };
      if (!transitions[command.action]?.includes(old.status)) throw new ViolationError("\u0648\u0636\u0639\u06CC\u062A \u062A\u062E\u0644\u0641 \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F\u0647 \u06CC\u0627 \u0627\u0642\u062F\u0627\u0645 \u0645\u062C\u0627\u0632 \u0646\u06CC\u0633\u062A.", 409);
      const status = { submit: "submitted", review: "review", approve: "approved", reject: "rejected", appeal: "appealed", reverse: "reversed" };
      next = { ...old, status: status[command.action] };
      if (["approve", "reverse"].includes(command.action)) {
        const evaluation = evaluations.get(`${old.employeeId}\0${old.periodId}`);
        if (!evaluation || evaluation.status !== "draft" || evaluation.stage === "completed") throw new ViolationError("\u06A9\u0633\u0631 \u06CC\u0627 \u0628\u0631\u06AF\u0634\u062A \u0628\u0631\u0627\u06CC \u067E\u0631\u0648\u0646\u062F\u0647 \u0646\u0647\u0627\u06CC\u06CC \u06CC\u0627 \u062F\u0648\u0631\u0647 \u0641\u0627\u0642\u062F \u067E\u0631\u0648\u0646\u062F\u0647 \u0641\u0639\u0627\u0644 \u0645\u062C\u0627\u0632 \u0646\u06CC\u0633\u062A.", 403);
        if (command.action === "approve") {
          if (!businessDateBelongsToPeriod(old.date, old.periodId)) throw new ViolationError("\u062A\u0627\u0631\u06CC\u062E \u062A\u062E\u0644\u0641 \u0628\u0647 \u0627\u06CC\u0646 \u062F\u0648\u0631\u0647 \u062A\u0639\u0644\u0642 \u0646\u062F\u0627\u0631\u062F\u061B \u06A9\u0633\u0631 \u0627\u0645\u062A\u06CC\u0627\u0632 \u0645\u062A\u0648\u0642\u0641 \u0634\u062F.", 403);
          const p = args.policy;
          const category = p.categories.find((c) => c.id === old.categoryId);
          const date = parseBusinessDate(old.date);
          if (!validViolationPolicy(p) || !p.active || date < parseBusinessDate(p.effectiveFrom) || date > parseBusinessDate(p.effectiveUntil) || !category || !Object.hasOwn(category.points, old.severity)) throw new ViolationError("\u0633\u06CC\u0627\u0633\u062A \u0645\u0635\u0648\u0628 \u0648 \u0641\u0639\u0627\u0644 \u0628\u0631\u0627\u06CC \u062A\u0627\u0631\u06CC\u062E \u062A\u062E\u0644\u0641 \u0645\u0648\u062C\u0648\u062F \u0646\u06CC\u0633\u062A.", 403);
          if (old.reporterId === args.actor.id || old.employeeId === args.actor.id) throw new ViolationError("\u062B\u0628\u062A\u200C\u06A9\u0646\u0646\u062F\u0647 \u0646\u0645\u06CC\u200C\u062A\u0648\u0627\u0646\u062F \u062A\u062E\u0644\u0641 \u062E\u0648\u062F\u0634 \u0631\u0627 \u062A\u0623\u06CC\u06CC\u062F \u06A9\u0646\u062F.", 403);
          if (category.attendanceRelated && (!("attendanceJustification" in command) || !text(command.attendanceJustification))) throw new ViolationError("\u0628\u0631\u0627\u06CC \u062C\u0644\u0648\u06AF\u06CC\u0631\u06CC \u0627\u0632 \u06A9\u0633\u0631 \u062F\u0648\u0628\u0627\u0631\u0647 \u06A9\u0633\u0631\u06CC\u060C \u062A\u0648\u062C\u06CC\u0647 \u0645\u0633\u062A\u0642\u0644 \u0645\u0635\u0648\u0628 \u0644\u0627\u0632\u0645 \u0627\u0633\u062A.", 403);
          next = { ...next, points: category.points[old.severity], policyVersion: p.version, policyCap: p.maximumDeduction };
        }
        affected.add(`${old.employeeId}\0${old.periodId}`);
      }
    }
    const reason = "reason" in command ? command.reason : next.description;
    next.history = [...next.history, { action: command.action, actorId: args.actor.id, at: args.now, reason, operationId: args.operationId }];
    byId.set(next.id, next);
    audit.push({ id: `audit:violation:${args.operationId}:${next.id}:${command.action}`, timestamp: args.now, actorId: args.actor.id, actorName: args.actor.name, actorRole: args.actor.role, action: `violation_${command.action}`, target: next.id, previousState: old || null, resultingState: next, result: "accepted" });
  }
  const records = [...byId.values()];
  const deduction = /* @__PURE__ */ new Map();
  for (const record of records) if (["approved", "appealed"].includes(record.status)) {
    const key = `${record.employeeId}\0${record.periodId}`;
    if (!affected.has(key)) continue;
    const value = deduction.get(key) || { sum: 0, cap: Infinity };
    value.sum += record.points;
    value.cap = Math.min(value.cap, record.policyCap ?? 0);
    deduction.set(key, value);
  }
  return { records, audit, evaluations: args.evaluations.map((e) => {
    const key = `${e.empId}\0${getEvaluationPeriodId(e)}`;
    if (!affected.has(key)) return e;
    const d = deduction.get(key);
    return { ...e, approvedDeduction: d ? Math.min(d.sum, d.cap) : 0 };
  }) };
}
__name(applyViolationCommands, "applyViolationCommands");

// ../src/utils/jobFamilyRegistry.ts
var JOB_FAMILIES = [
  ["machining", "\u0627\u067E\u0631\u0627\u062A\u0648\u0631\u06CC \u0645\u0627\u0634\u06CC\u0646\u200C\u06A9\u0627\u0631\u06CC\u060C CNC\u060C \u062A\u0631\u0627\u0646\u0633\u0641\u0631\u060C \u062A\u06A9\u200C\u0645\u062D\u0648\u0631 \u0648 \u0634\u0634\u200C\u0645\u062D\u0648\u0631", ["\u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u0645\u0627\u0634\u06CC\u0646\u06A9\u0627\u0631\u06CC"]],
  ["forge", "\u0627\u067E\u0631\u0627\u062A\u0648\u0631\u06CC \u0641\u0648\u0631\u062C\u060C \u0622\u0631\u0627\u06CC\u0634 \u0648 \u0639\u0645\u0644\u06CC\u0627\u062A \u0648\u0627\u0628\u0633\u062A\u0647", ["\u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u0641\u0648\u0631\u062C"]],
  ["finishing", "\u0627\u067E\u0631\u0627\u062A\u0648\u0631\u06CC \u0622\u0628\u06A9\u0627\u0631\u06CC \u0648 \u0639\u0645\u0644\u06CC\u0627\u062A \u062A\u06A9\u0645\u06CC\u0644\u06CC", ["\u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u0622\u0628\u06A9\u0627\u0631\u06CC", "\u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u067E\u0644\u06CC\u0633\u0647 \u062E\u0634\u06A9 \u06A9\u0646"]],
  ["assembly", "\u0645\u0648\u0646\u062A\u0627\u0698 \u0648 \u0628\u0633\u062A\u0647\u200C\u0628\u0646\u062F\u06CC", ["\u06A9\u0627\u0631\u06AF\u0631 \u0645\u0648\u0646\u062A\u0627\u0698 \u0648 \u0628\u0633\u062A\u0647 \u0628\u0646\u062F\u06CC", "\u0627\u067E\u0631\u0627\u062A\u0648\u0631 \u0645\u0648\u0646\u062A\u0627\u0698 \u0648 \u0628\u0633\u062A\u0647 \u0628\u0646\u062F\u06CC", "\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0645\u0648\u0646\u062A\u0627\u0698 \u0648 \u0628\u0633\u062A\u0647 \u0628\u0646\u062F\u06CC"]],
  ["setup", "\u062A\u06A9\u0646\u0633\u06CC\u0646\u200C\u0647\u0627\u06CC \u062A\u0646\u0638\u06CC\u0645 \u0648 \u0646\u0638\u0627\u0645\u200C\u062F\u0647\u0646\u062F\u0647", ["\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0646\u0638\u0627\u0645 \u062F\u0647\u0646\u062F\u0647"]],
  ["mechanical", "\u0645\u06A9\u0627\u0646\u06CC\u06A9 \u062A\u0639\u0645\u06CC\u0631\u0627\u062A \u0648 \u0646\u06AF\u0647\u062F\u0627\u0631\u06CC", ["\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0645\u06A9\u0627\u0646\u06CC\u06A9"]],
  ["electrical", "\u0628\u0631\u0642\u060C \u0627\u0644\u06A9\u062A\u0631\u0648\u0646\u06CC\u06A9 \u0648 \u0627\u062A\u0648\u0645\u0627\u0633\u06CC\u0648\u0646", ["\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0628\u0631\u0642 \u0648 \u0627\u0644\u06A9\u062A\u0631\u0648\u0646\u06CC\u06A9", "\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0627\u062A\u0648\u0645\u0627\u0633\u06CC\u0648\u0646 \u0635\u0646\u0639\u062A\u06CC", "\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u0627\u062A\u0648\u0645\u0627\u0633\u06CC\u0648\u0646 \u0635\u0646\u0639\u062A\u06CC"]],
  ["preventive", "\u0646\u062A \u0646\u06AF\u0647\u062F\u0627\u0631\u06CC \u0648 \u067E\u0627\u06CC\u0634 \u062A\u062C\u0647\u06CC\u0632\u0627\u062A", ["\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0646\u06AF\u0647\u062F\u0627\u0634\u062A \u062A\u062C\u0647\u06CC\u0632\u0627\u062A", "\u06A9\u0627\u0631\u0645\u0646\u062F \u0646\u06AF\u0647\u062F\u0627\u0631\u06CC \u0648 \u062A\u0639\u0645\u06CC\u0631\u0627\u062A"]],
  ["tooling", "\u062A\u0639\u0645\u06CC\u0631\u0627\u062A \u0642\u0627\u0644\u0628\u060C \u0627\u0628\u0632\u0627\u0631 \u0648 \u062A\u062C\u0647\u06CC\u0632\u0627\u062A", ["\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0642\u0627\u0644\u0628", "\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u0642\u0627\u0644\u0628", "\u062A\u06A9\u0646\u0633\u06CC\u0646 \u0627\u0628\u0632\u0627\u0631", "\u062A\u06A9\u0646\u0633\u06CC\u0646 \u062C\u0648\u0634\u06A9\u0627\u0631\u06CC"]],
  ["quality", "\u06A9\u0646\u062A\u0631\u0644 \u06A9\u06CC\u0641\u06CC\u062A \u062D\u06CC\u0646 \u0641\u0631\u0627\u06CC\u0646\u062F \u0648 \u0646\u0647\u0627\u06CC\u06CC", ["\u062A\u06A9\u0646\u0633\u06CC\u0646 \u06A9\u0646\u062A\u0631\u0644 \u06A9\u06CC\u0641\u06CC\u062A", "\u062A\u06A9\u0646\u0633\u06CC\u0646 \u06A9\u0646\u062A\u0631\u0644 \u06A9\u06CC\u0641\u06CC\u062A \u062D\u06CC\u0646 \u0641\u0631\u0627\u06CC\u0646\u062F", "\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u06A9\u0646\u062A\u0631\u0644 \u06A9\u06CC\u0641\u06CC\u062A"]],
  ["assurance", "\u062A\u0636\u0645\u06CC\u0646 \u06A9\u06CC\u0641\u06CC\u062A \u0648 \u0622\u0632\u0645\u0627\u06CC\u0634\u06AF\u0627\u0647", ["\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u062A\u0636\u0645\u06CC\u0646 \u06A9\u06CC\u0641\u06CC\u062A", "\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u0622\u0632\u0645\u0627\u06CC\u0634\u06AF\u0627\u0647"]],
  ["warehouse", "\u0627\u0646\u0628\u0627\u0631\u060C \u0644\u062C\u0633\u062A\u06CC\u06A9 \u0648 \u0644\u06CC\u0641\u062A\u0631\u0627\u06A9", ["\u0627\u0646\u0628\u0627\u0631\u062F\u0627\u0631", "\u0631\u0627\u0646\u0646\u062F\u0647 \u0644\u06CC\u0641\u062A\u0631\u0627\u06A9"]],
  ["statistics", "\u0622\u0645\u0627\u0631 \u0648 \u0627\u0637\u0644\u0627\u0639\u0627\u062A \u062A\u0648\u0644\u06CC\u062F", ["\u06A9\u0627\u0631\u0645\u0646\u062F \u0622\u0645\u0627\u0631 \u0648 \u0627\u0637\u0644\u0627\u0639\u0627\u062A"]],
  ["planning", "\u0628\u0631\u0646\u0627\u0645\u0647\u200C\u0631\u06CC\u0632\u06CC \u0648 \u06A9\u0646\u062A\u0631\u0644 \u062A\u0648\u0644\u06CC\u062F", ["\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u0628\u0631\u0646\u0627\u0645\u0647 \u0631\u06CC\u0632\u06CC \u062A\u0648\u0644\u06CC\u062F"]],
  ["engineering", "\u0637\u0631\u0627\u062D\u06CC \u0648 \u0645\u0647\u0646\u062F\u0633\u06CC \u0648 \u062A\u062D\u0642\u06CC\u0642 \u0648 \u062A\u0648\u0633\u0639\u0647", ["\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u0637\u0631\u0627\u062D\u06CC \u0648 \u0645\u0647\u0646\u062F\u0633\u06CC", "\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u062A\u062D\u0642\u06CC\u0642 \u0648 \u062A\u0648\u0633\u0639\u0647"]],
  ["improvement", "\u0628\u0647\u0628\u0648\u062F \u0641\u0631\u0627\u06CC\u0646\u062F\u0647\u0627 \u0648 \u0633\u06CC\u0633\u062A\u0645\u200C\u0647\u0627 \u0648 \u0631\u0648\u0634\u200C\u0647\u0627", ["\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u0628\u0647\u0628\u0648\u062F \u0641\u0631\u0622\u06CC\u0646\u062F", "\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 \u0633\u06CC\u0633\u062A\u0645\u0647\u0627 \u0648 \u0631\u0648\u0634\u0647\u0627"]],
  ["administrative", "\u0645\u0646\u0627\u0628\u0639 \u0627\u0646\u0633\u0627\u0646\u06CC\u060C \u0627\u062F\u0627\u0631\u06CC \u0648 \u062D\u0633\u0627\u0628\u062F\u0627\u0631\u06CC", ["\u06A9\u0627\u0631\u0645\u0646\u062F \u0627\u062F\u0627\u0631\u06CC", "\u06A9\u0627\u0631\u062F\u0627\u0646 \u0627\u062F\u0627\u0631\u06CC", "\u0645\u0633\u0626\u0648\u0644 \u062F\u0641\u062A\u0631", "\u06A9\u0627\u0631\u0645\u0646\u062F \u067E\u0630\u06CC\u0631\u0634"]],
  ["hse", "HSE \u0648 \u0627\u06CC\u0645\u0646\u06CC", ["\u06A9\u0627\u0631\u0634\u0646\u0627\u0633 HSE"]],
  ["support", "\u062E\u062F\u0645\u0627\u062A\u060C \u062D\u0645\u0644\u200C\u0648\u0646\u0642\u0644\u060C \u067E\u0634\u062A\u06CC\u0628\u0627\u0646\u06CC \u0648 \u0631\u0633\u062A\u0648\u0631\u0627\u0646", ["\u06A9\u0627\u0631\u06AF\u0631 \u062E\u062F\u0645\u0627\u062A", "\u06A9\u0627\u0631\u06AF\u0631 \u0631\u0633\u062A\u0648\u0631\u0627\u0646", "\u0631\u0627\u0646\u0646\u062F\u0647"]],
  ["supervisory", "\u0633\u0631\u06AF\u0631\u0648\u0647\u200C\u0647\u0627\u060C \u0645\u0633\u0626\u0648\u0644\u0627\u0646 \u0634\u06CC\u0641\u062A \u0648 \u0633\u0631\u067E\u0631\u0633\u062A\u0627\u0646", ["\u0633\u0631\u067E\u0631\u0633\u062A \u0645\u0627\u0634\u06CC\u0646\u06A9\u0627\u0631\u06CC", "\u0645\u0633\u0626\u0648\u0644 \u0634\u06CC\u0641\u062A \u0645\u0627\u0634\u06CC\u0646\u06A9\u0627\u0631\u06CC", "\u0645\u0633\u0626\u0648\u0644 \u0634\u06CC\u0641\u062A \u0641\u0648\u0631\u062C", "\u0633\u0631\u067E\u0631\u0633\u062A \u0641\u0648\u0631\u062C", "\u0633\u0631\u067E\u0631\u0633\u062A \u0622\u0628\u06A9\u0627\u0631\u06CC", "\u0633\u0631\u067E\u0631\u0633\u062A \u0645\u0648\u0646\u062A\u0627\u0698 \u0648 \u0628\u0633\u062A\u0647 \u0628\u0646\u062F\u06CC", "\u0645\u0633\u0626\u0648\u0644 \u0645\u0648\u0646\u062A\u0627\u0698 \u0648 \u0628\u0633\u062A\u0647 \u0628\u0646\u062F\u06CC", "\u0633\u0631\u067E\u0631\u0633\u062A \u0628\u0631\u0642 \u0648 \u0627\u0644\u06A9\u062A\u0631\u0648\u0646\u06CC\u06A9", "\u0645\u0633\u0626\u0648\u0644 \u0645\u06A9\u0627\u0646\u06CC\u06A9", "\u0645\u0633\u0626\u0648\u0644 \u0646\u06AF\u0647\u062F\u0627\u0634\u062A \u062A\u062C\u0647\u06CC\u0632\u0627\u062A", "\u0645\u0633\u0626\u0648\u0644 \u0627\u062A\u0648\u0645\u0627\u0633\u06CC\u0648\u0646 \u0635\u0646\u0639\u062A\u06CC", "\u0645\u0633\u0626\u0648\u0644 \u062A\u062C\u0647\u06CC\u0632\u0627\u062A", "\u0633\u0631\u067E\u0631\u0633\u062A \u06A9\u0646\u062A\u0631\u0644 \u06A9\u06CC\u0641\u06CC\u062A \u0648 \u0622\u0632\u0645\u0627\u06CC\u0634\u06AF\u0627\u0647", "\u0633\u0631\u067E\u0631\u0633\u062A \u0627\u0646\u0628\u0627\u0631", "\u0633\u0631\u067E\u0631\u0633\u062A \u0628\u0631\u0646\u0627\u0645\u0647 \u0631\u06CC\u0632\u06CC \u062A\u0648\u0644\u06CC\u062F", "\u0633\u0631\u067E\u0631\u0633\u062A \u0637\u0631\u0627\u062D\u06CC \u0648 \u0645\u0647\u0646\u062F\u0633\u06CC", "\u0631\u0626\u06CC\u0633 \u0628\u0647\u0628\u0648\u062F \u0641\u0631\u0622\u06CC\u0646\u062F", "\u0633\u0631\u067E\u0631\u0633\u062A \u0633\u06CC\u0633\u062A\u0645 \u0647\u0627 \u0648 \u0631\u0648\u0634 \u0647\u0627", "\u0633\u0631\u067E\u0631\u0633\u062A \u0627\u062F\u0627\u0631\u06CC \u0648 \u0645\u0646\u0627\u0628\u0639 \u0627\u0646\u0633\u0627\u0646\u06CC", "\u0645\u0633\u0626\u0648\u0644 \u062E\u062F\u0645\u0627\u062A"]],
  ["management", "\u0645\u062F\u06CC\u0631\u0627\u0646 \u0648\u0627\u062D\u062F\u0647\u0627 \u0648 \u0645\u062F\u06CC\u0631\u06CC\u062A \u0627\u0631\u0634\u062F", ["\u0645\u062F\u06CC\u0631 \u062A\u0648\u0644\u06CC\u062F", "\u0645\u062F\u06CC\u0631 \u0639\u0627\u0645\u0644"]]
];
function validateApprovedFamilyAssignment(assignment, profiles, criteria) {
  const profile = profiles.find((p) => p.id === assignment.profileId);
  return Boolean(JOB_FAMILIES.some(([id]) => id === assignment.familyId) && typeof assignment.approvalReference === "string" && assignment.approvalReference.trim() && (assignment.personnelCode === void 0 || typeof assignment.personnelCode === "string" && assignment.personnelCode.trim() && typeof assignment.jobTitle === "string" && assignment.jobTitle.trim() && typeof assignment.internalJob === "string" && assignment.internalJob.trim()) && profile && profile.items.length && Math.abs(profile.items.reduce((sum, item) => sum + item.weight, 0) - 100) < 1e-4 && profile.items.every((item) => item.weight > 0 && criteria.some((c) => c.id === item.cid)));
}
__name(validateApprovedFamilyAssignment, "validateApprovedFamilyAssignment");

// ../cloudflare/stateEngine.ts
var StateStoreUnavailable = class extends Error {
  constructor(code, operationId, writePhase = "kv_read", committed = false, elapsedMs = 0) {
    super(code);
    this.code = code;
    this.operationId = operationId;
    this.writePhase = writePhase;
    this.committed = committed;
    this.elapsedMs = elapsedMs;
    this.name = "StateStoreUnavailable";
  }
  static {
    __name(this, "StateStoreUnavailable");
  }
};
var queuedStateWrites = 0;
var activeStateWrites = 0;
async function safeActorReference(actorId) {
  const digest2 = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(actorId));
  return Array.from(new Uint8Array(digest2).slice(0, 6), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(safeActorReference, "safeActorReference");
async function logStateStoreFailure(error, context, details) {
  let actorRef = "unavailable";
  try {
    if (context.data.session?.id) actorRef = await safeActorReference(context.data.session.id);
  } catch {
  }
  const requestContext = details;
  console.error(JSON.stringify({
    event: "chalak_state_store_failure",
    requestType: context.request.method === "GET" ? "state.read" : "state.write",
    operationId: error.operationId || null,
    actor: { ref: actorRef, role: context.data.session?.role || "anonymous" },
    payloadBytes: requestContext.requestBytes ?? 0,
    baseRevision: Number.isInteger(requestContext.baseRevision) ? requestContext.baseRevision : null,
    serverRevision: Number.isInteger(requestContext.serverRevision) ? requestContext.serverRevision : null,
    writePhase: error.writePhase,
    kvReadPhase: error.writePhase === "kv_read" ? "failed" : "complete",
    kvWritePhase: error.writePhase === "kv_state_write" || error.writePhase === "kv_metadata_write" ? "failed" : "not_reached",
    elapsedMs: Math.max(error.elapsedMs, Date.now() - (requestContext.startedAt || Date.now())),
    queueDepth: queuedStateWrites,
    inFlightWrites: activeStateWrites,
    retryCount: requestContext.retryCount ?? 0,
    responseReason: error.code,
    committed: error.committed
  }));
}
__name(logStateStoreFailure, "logStateStoreFailure");
var NON_ADMIN_WRITABLE_KEYS = /* @__PURE__ */ new Set([
  "pe_evaluations",
  "pe_delegations",
  "pe_notifications",
  "pe_lattice_okrs",
  "pe_lattice_one_on_ones",
  "pe_lattice_kudos",
  "pe_tickets"
]);
async function readState(env, operationId) {
  if (!env.TRANSACTION_STORE) throw new StateStoreUnavailable("transaction_store_unconfigured", operationId);
  return env.TRANSACTION_STORE.read();
}
__name(readState, "readState");
function allowedEmployeeIds(state, session) {
  const employees = getEmployees(state);
  const actor = getActor(state, session);
  const policy = getPermissionPolicy(state);
  const allowed = /* @__PURE__ */ new Set();
  if (!actor) return allowed;
  for (const employee of employees) {
    if (["evaluations", "workflow", "cartable"].some(
      (module) => authorize(actor, module, "view", employee, policy).allowed
    ) || canImport(actor, "mis", employee, policy).allowed || canImport(actor, "kasra", employee, policy).allowed) allowed.add(employee.id);
  }
  return allowed;
}
__name(allowedEmployeeIds, "allowedEmployeeIds");
function getEmployees(state) {
  return Array.isArray(state.pe_employees) ? state.pe_employees : [];
}
__name(getEmployees, "getEmployees");
function getProfiles(state) {
  return Array.isArray(state.pe_profiles) ? state.pe_profiles : [];
}
__name(getProfiles, "getProfiles");
function getDelegations(state) {
  return Array.isArray(state.pe_delegations) ? state.pe_delegations : [];
}
__name(getDelegations, "getDelegations");
function getPermissionPolicy(state) {
  const value = state.pe_granular_permissions;
  return value?.version === 1 ? { ...DEFAULT_GRANULAR_PERMISSION_POLICY, ...value } : DEFAULT_GRANULAR_PERMISSION_POLICY;
}
__name(getPermissionPolicy, "getPermissionPolicy");
function getRouteRules(state) {
  return Array.isArray(state.pe_route_rules) ? state.pe_route_rules : DEFAULT_ROUTE_RULES;
}
__name(getRouteRules, "getRouteRules");
function validCriterionScoringConfiguration(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const criterion = value;
  if (typeof criterion.id !== "string" || !criterion.id) return false;
  if (criterion.dir !== void 0 && criterion.dir !== "more" && criterion.dir !== "less") return false;
  if (criterion.allowedScoreMin !== void 0 && typeof criterion.allowedScoreMin !== "number") return false;
  if (criterion.allowedScoreMax !== void 0 && typeof criterion.allowedScoreMax !== "number") return false;
  if (!validManualScoreLimits(criterion.allowedScoreMin, criterion.allowedScoreMax)) return false;
  if (criterion.targetValue !== void 0 && (typeof criterion.targetValue !== "number" || !Number.isFinite(criterion.targetValue))) return false;
  if (criterion.scoreThresholds !== void 0) {
    const thresholds = criterion.scoreThresholds;
    if (!thresholds || typeof thresholds !== "object" || !["score5", "score4", "score3", "score2"].every((key) => typeof thresholds[key] === "number" && Number.isFinite(thresholds[key]))) return false;
    if (!thresholdsFollowDirection(thresholds, criterion.dir || "more")) return false;
  }
  return true;
}
__name(validCriterionScoringConfiguration, "validCriterionScoringConfiguration");
function getActor(state, session) {
  if (session.role === "admin") return { id: session.id, name: session.name, code: "ADMIN", profileId: "", unit: "", role: "admin", username: session.username };
  return getEmployees(state).find((employee) => employee.id === session.id && employee.role === session.role) || null;
}
__name(getActor, "getActor");
function notificationFor(evaluation, actor, log, isCreation, employeeIds) {
  if (!isCreation && !log) return null;
  const recipientId = evaluation.currentAssigneeId;
  if (!recipientId || recipientId === actor.id || !employeeIds.has(recipientId)) return null;
  const action = log?.action;
  const eventType = isCreation ? "evaluation_started" : action === "reject_to_employee" || action === "reject_to_supervisor" ? "workflow_returned" : action === "reassign_assignee" ? "workflow_reassigned" : action === "route_hse" ? "hse_review_requested" : action === "complete_hse_review" ? "hse_review_completed" : action === "submit_self" ? "workflow_submitted" : "workflow_advanced";
  const eventKey = `${evaluation.id}:${log?.id || "created"}`;
  return {
    id: `notification:${eventKey}`,
    eventKey,
    recipientId,
    eventType,
    title: eventType === "evaluation_started" ? "\u0627\u0631\u0632\u06CC\u0627\u0628\u06CC \u062C\u062F\u06CC\u062F" : eventType === "workflow_returned" ? "\u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0631\u0627\u06CC \u0627\u0635\u0644\u0627\u062D \u0628\u0627\u0632\u06AF\u0634\u062A" : eventType === "workflow_reassigned" ? "\u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0647 \u0634\u0645\u0627 \u0627\u0631\u062C\u0627\u0639 \u0634\u062F" : eventType === "hse_review_requested" ? "\u062F\u0631\u062E\u0648\u0627\u0633\u062A \u0628\u0631\u0631\u0633\u06CC HSE" : eventType === "hse_review_completed" ? "\u0628\u0631\u0631\u0633\u06CC HSE \u062A\u06A9\u0645\u06CC\u0644 \u0634\u062F" : "\u0627\u0642\u062F\u0627\u0645 \u062C\u062F\u06CC\u062F \u062F\u0631 \u0627\u0631\u0632\u06CC\u0627\u0628\u06CC",
    message: eventType === "hse_review_requested" ? `${actor.name} \u067E\u0631\u0648\u0646\u062F\u0647 ${evaluation.id} \u0631\u0627 \u0628\u0631\u0627\u06CC \u0628\u0631\u0631\u0633\u06CC HSE \u0627\u0631\u062C\u0627\u0639 \u062F\u0627\u062F.` : eventType === "hse_review_completed" ? `\u0628\u0631\u0631\u0633\u06CC HSE \u067E\u0631\u0648\u0646\u062F\u0647 ${evaluation.id} \u062A\u06A9\u0645\u06CC\u0644 \u0634\u062F.` : `\u067E\u0631\u0648\u0646\u062F\u0647 \u0627\u0631\u0632\u06CC\u0627\u0628\u06CC ${evaluation.id} \u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u067E\u06CC\u06AF\u06CC\u0631\u06CC \u0634\u0645\u0627\u0633\u062A.`,
    targetTab: eventType === "evaluation_started" ? "evaluations" : "workflow",
    evaluationId: evaluation.id,
    taskKey: workflowTaskIdentity(evaluation),
    actorId: actor.id,
    createdAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
__name(notificationFor, "notificationFor");
function getNotifications(state) {
  return Array.isArray(state.pe_notifications) ? state.pe_notifications : [];
}
__name(getNotifications, "getNotifications");
function evaluationAuditState(evaluation) {
  const record = evaluation;
  return {
    stage: record.stage,
    status: record.status,
    currentAssigneeId: record.currentAssigneeId,
    bulkOperationId: record.bulkOperationId
  };
}
__name(evaluationAuditState, "evaluationAuditState");
function evaluationScoreChanges(before, after) {
  if (!before) return [];
  const oldScores = new Map((before.scores || []).map((score) => [score.cid, score]));
  return (after.scores || []).flatMap((score) => {
    const previous = oldScores.get(score.cid);
    if (!previous || JSON.stringify(previous) === JSON.stringify(score)) return [];
    return [{ cid: score.cid, previous: { value: previous.value, self: previous.self, peer: previous.peer, doc: previous.doc, sourceType: previous.sourceType, sourceBreakdown: previous.sourceBreakdown }, resulting: { value: score.value, self: score.self, peer: score.peer, doc: score.doc, sourceType: score.sourceType, sourceBreakdown: score.sourceBreakdown } }];
  });
}
__name(evaluationScoreChanges, "evaluationScoreChanges");
function validNotificationReadUpdates(changes, current, session) {
  if (!Array.isArray(changes.pe_notifications)) return true;
  const old = new Map(getNotifications(current).map((item) => [item.id, item]));
  return changes.pe_notifications.every((next) => {
    const previous = old.get(next?.id);
    if (!previous) return false;
    return previous.recipientId === session.id && next.recipientId === previous.recipientId && next.eventKey === previous.eventKey && next.title === previous.title && next.message === previous.message && next.actorId === previous.actorId && next.createdAt === previous.createdAt && next.evaluationId === previous.evaluationId && next.targetTab === previous.targetTab && next.taskKey === previous.taskKey && next.resolvedAt === previous.resolvedAt && next.resolvedReason === previous.resolvedReason && (next.readAt === previous.readAt || typeof next.readAt === "string" && !previous.readAt);
  });
}
__name(validNotificationReadUpdates, "validNotificationReadUpdates");
function delegatedAuthority(existing, incoming, state, session) {
  const actor = getEmployees(state).find((employee) => employee.id === session.id && employee.role === session.role);
  if (!actor) return false;
  const employees = getEmployees(state);
  const delegations = getDelegations(state);
  if (incoming) {
    const latest = incoming.history?.[0];
    if (!latest || latest.actorId !== session.id || !latest.delegationId || latest.id === existing.history?.[0]?.id) return false;
    const action = workflowPermissionForTransition(
      latest.action,
      existing.stage || "self_review"
    );
    if (!action) return false;
    const auth = canPerformWorkflowAction(actor, existing, action, { employees, delegations });
    return auth.authorized && auth.delegation?.id === latest.delegationId;
  }
  return ["approve", "reject", "reassign", "advance"].some(
    (action) => Boolean(canPerformWorkflowAction(actor, existing, action, { employees, delegations }).delegation)
  );
}
__name(delegatedAuthority, "delegatedAuthority");
function authorizedDelegationWrite(incoming, existing, state, session) {
  if (!incoming?.id || incoming.delegateId === session.id || session.role !== "admin" && incoming.delegatorId !== session.id) return false;
  if (session.role === "admin" && existing) {
    if (JSON.stringify(incoming) === JSON.stringify(existing)) return true;
    return incoming.status === "revoked" && existing.status !== "revoked" && incoming.revokedById === session.id && incoming.delegatorId === existing.delegatorId && incoming.delegateId === existing.delegateId && incoming.action === existing.action && incoming.scope === existing.scope && incoming.targetEmpId === existing.targetEmpId && incoming.targetUnit === existing.targetUnit && incoming.startDate === existing.startDate && incoming.endDate === existing.endDate && incoming.createdAt === existing.createdAt && incoming.reason === existing.reason && Number.isFinite(incoming.revokedAt);
  }
  const employees = getEmployees(state);
  const delegator = employees.find((employee) => employee.id === session.id && employee.role === session.role);
  if (!delegator || !employees.some((employee) => employee.id === incoming.delegateId) || !canDelegate(delegator, incoming.action, employees, getDelegations(state))) return false;
  if (existing) {
    return existing.delegatorId === session.id && (JSON.stringify(incoming) === JSON.stringify(existing) || incoming.status === "revoked" && existing.status !== "revoked" && incoming.revokedById === session.id && incoming.delegateId === existing.delegateId && incoming.action === existing.action && incoming.scope === existing.scope && incoming.targetEmpId === existing.targetEmpId && incoming.targetUnit === existing.targetUnit && incoming.startDate === existing.startDate && incoming.endDate === existing.endDate);
  }
  if (!Number.isFinite(incoming.startDate) || !Number.isFinite(incoming.endDate) || incoming.startDate > incoming.endDate || !["active", "future"].includes(incoming.status)) return false;
  if (incoming.scope === "employee") {
    const target = employees.find((employee) => employee.id === incoming.targetEmpId);
    return Boolean(target && (session.role === "supervisor" ? isWithinSupervisorScope(delegator, target, employees) : target.id === session.id));
  }
  if (incoming.scope === "unit" && session.role === "supervisor") {
    return Boolean(incoming.targetUnit && employees.some((employee) => employee.unit === incoming.targetUnit && isWithinSupervisorScope(delegator, employee, employees)));
  }
  return false;
}
__name(authorizedDelegationWrite, "authorizedDelegationWrite");
function canAccessEvaluation(evaluation, state, session, scopedAllowedIds) {
  if (session.role === "admin") return true;
  if (delegatedAuthority(evaluation, void 0, state, session)) return true;
  const allowedIds = scopedAllowedIds || allowedEmployeeIds(state, session);
  if (allowedIds.has(evaluation.empId)) return true;
  const actor = getActor(state, session);
  if (!actor || evaluation.currentAssigneeId !== session.id) return false;
  const policy = getPermissionPolicy(state);
  const hasExplicitViewGrant = ["evaluations", "workflow", "cartable"].some((module) => {
    const userGrants = policy.users?.[session.id]?.[module];
    const roleGrants = policy.roles?.[actor.role]?.[module];
    return Boolean(
      userGrants && Object.prototype.hasOwnProperty.call(userGrants, "view") || roleGrants && Object.prototype.hasOwnProperty.call(roleGrants, "view")
    );
  });
  return !hasExplicitViewGrant;
}
__name(canAccessEvaluation, "canAccessEvaluation");
function hasAuthorizedEvaluationChanges(current, changes, session, sourceImport) {
  if (!validNotificationReadUpdates(changes, current, session)) return false;
  if (sourceImport && isMasterDataSourceImportContext(sourceImport)) return validateMasterDataImport(current, changes, session, sourceImport);
  if (sourceImport && isProtectedSourceImportContext(sourceImport) && Object.keys(changes).some((key) => key !== "pe_evaluations" && key !== "pe_notifications")) return false;
  const protectedSourceImport = sourceImport && isProtectedSourceImportContext(sourceImport) ? sourceImport : void 0;
  if (session.role === "admin") {
    if ("pe_audit_logs" in changes && JSON.stringify(changes.pe_audit_logs) !== JSON.stringify(current.pe_audit_logs || [])) return false;
    if (!safeAdminMasterDataChanges(current, changes)) return false;
    const actor2 = getActor(current, session);
    if (!actor2) return false;
    if ("pe_criteria" in changes && (!Array.isArray(changes.pe_criteria) || !changes.pe_criteria.every(validCriterionScoringConfiguration))) return false;
    const delegationsById2 = new Map(getDelegations(current).map((item) => [item.id, item]));
    if (Array.isArray(changes.pe_delegations) && !changes.pe_delegations.every((incoming) => authorizedDelegationWrite(incoming, delegationsById2.get(incoming?.id), current, session))) return false;
    if (!Array.isArray(changes.pe_evaluations)) return true;
    const byId2 = new Map((Array.isArray(current.pe_evaluations) ? current.pe_evaluations : []).map((item) => [item.id, item]));
    const incomingIds = new Set(changes.pe_evaluations.map((item) => item.id));
    if ([...byId2.values()].some((item) => !incomingIds.has(item.id) && (item.status === "locked" || item.stage === "completed"))) return false;
    const validationContext = { actor: actor2, employees: getEmployees(current), criteria: current.pe_criteria || [], profiles: getProfiles(current), delegations: getDelegations(current), permissionPolicy: getPermissionPolicy(current), routeRules: getRouteRules(current), sourceImport: protectedSourceImport };
    return changes.pe_evaluations.every((incoming) => byId2.get(incoming?.id) === incoming || validateEvaluationWrite(byId2.get(incoming?.id), incoming, validationContext) === null);
  }
  if (Object.keys(changes).some((key) => !NON_ADMIN_WRITABLE_KEYS.has(key))) return false;
  const byId = new Map((Array.isArray(current.pe_evaluations) ? current.pe_evaluations : []).map((item) => [item.id, item]));
  const actor = getActor(current, session);
  if (Array.isArray(changes.pe_evaluations) && (!actor || !changes.pe_evaluations.every((incoming) => {
    const existing = byId.get(incoming?.id);
    return validateEvaluationWrite(existing, incoming, {
      actor,
      employees: getEmployees(current),
      criteria: current.pe_criteria || [],
      profiles: getProfiles(current),
      delegations: getDelegations(current),
      permissionPolicy: getPermissionPolicy(current),
      routeRules: getRouteRules(current),
      sourceImport: protectedSourceImport
    }) === null;
  }))) return false;
  const delegationsById = new Map(getDelegations(current).map((item) => [item.id, item]));
  if (Array.isArray(changes.pe_delegations) && !changes.pe_delegations.every((incoming) => authorizedDelegationWrite(incoming, delegationsById.get(incoming?.id), current, session))) return false;
  return true;
}
__name(hasAuthorizedEvaluationChanges, "hasAuthorizedEvaluationChanges");
function safeDenialReason(failure) {
  if (failure === "owner_change_requires_reassignment") return "workflow_owner_mismatch";
  if (failure === "mis_value_read_only") return "source_owned_value_read_only";
  if (failure === "kasra_import_not_authorized") return "kasra_import_not_authorized";
  if (failure === "mis_import_not_authorized") return "mis_import_not_authorized";
  if (failure === "employee_import_not_authorized") return "employee_import_not_authorized";
  if (failure === "criteria_import_not_authorized") return "criteria_import_not_authorized";
  if (failure === "source_import_invalid") return "source_import_invalid";
  if (failure === "completed_immutable") return "finalized_record_locked";
  if (failure === "score_limit_exceeded") return "score_limit_exceeded";
  if (failure === "missing_required_input") return "missing_required_input";
  if (["score_stage_denied", "invalid_transition", "transition_missing_history", "ceiling_exceeded"].includes(failure)) return "stage_not_authorized";
  return "permission_denied";
}
__name(safeDenialReason, "safeDenialReason");
function diagnoseStateWriteDenial(current, changes, session, sourceImport) {
  if (sourceImport && isMasterDataSourceImportContext(sourceImport)) {
    const actor2 = getActor(current, session);
    const importType = sourceImport.importType === "EMPLOYEE" ? "employee" : "criteria";
    const unauthorizedReason = sourceImport.importType === "EMPLOYEE" ? "employee_import_not_authorized" : "criteria_import_not_authorized";
    if (!actor2 || !canImport(actor2, importType, void 0, getPermissionPolicy(current)).allowed) {
      return { reason: unauthorizedReason };
    }
    if (sourceImport.importType === "EMPLOYEE" && Array.isArray(changes.pe_employees)) {
      const currentById = new Map(getEmployees(current).map((employee) => [employee.id, employee]));
      for (const employee of changes.pe_employees) {
        const previous = currentById.get(employee?.id);
        if (JSON.stringify(previous) === JSON.stringify(employee)) continue;
        const scoped = canImport(actor2, "employee", previous || employee, getPermissionPolicy(current));
        if (!scoped.allowed) return { reason: "outside_scope" };
      }
      return { reason: "source_import_invalid" };
    }
    if (sourceImport.importType === "CRITERIA" && Array.isArray(changes.pe_criteria) && !changes.pe_criteria.every(validCriterionScoringConfiguration)) {
      return { reason: "invalid_criterion_configuration" };
    }
    return { reason: "source_import_invalid" };
  }
  if (session.role === "admin" && "pe_criteria" in changes && (!Array.isArray(changes.pe_criteria) || !changes.pe_criteria.every(validCriterionScoringConfiguration))) {
    return { reason: "invalid_criterion_configuration" };
  }
  const actor = getActor(current, session);
  if (actor && Array.isArray(changes.pe_evaluations)) {
    const byId = new Map((Array.isArray(current.pe_evaluations) ? current.pe_evaluations : []).map((item) => [item.id, item]));
    for (const incoming of changes.pe_evaluations) {
      const existing = byId.get(incoming?.id);
      const failure = validateEvaluationWrite(existing, incoming, {
        actor,
        employees: getEmployees(current),
        criteria: current.pe_criteria || [],
        profiles: getProfiles(current),
        delegations: getDelegations(current),
        permissionPolicy: getPermissionPolicy(current),
        routeRules: getRouteRules(current),
        sourceImport: sourceImport && isProtectedSourceImportContext(sourceImport) ? sourceImport : void 0
      });
      if (!failure) continue;
      if (failure === "permission_denied" && existing) {
        const employee = getEmployees(current).find((item) => item.id === existing.empId);
        const scope = employee ? authorize(actor, "evaluations", "edit", employee, getPermissionPolicy(current)) : null;
        if (scope?.reason.includes("outside authorized employee scope")) return { reason: "outside_scope" };
      }
      const visible = Boolean(existing && canAccessEvaluation(existing, current, session));
      return {
        reason: safeDenialReason(failure),
        ...visible ? { recordId: existing.id } : {},
        ...failure === "missing_required_input" ? { missingRequirements: getFinalizationInputIssues(incoming, current.pe_criteria || []) } : {}
      };
    }
  }
  return { reason: "permission_denied" };
}
__name(diagnoseStateWriteDenial, "diagnoseStateWriteDenial");
function safeWriteDenialResponse(current, changes, session, sourceImport) {
  const denial = diagnoseStateWriteDenial(current, changes, session, sourceImport);
  const messages = {
    workflow_owner_mismatch: "\u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0647 \u0645\u0633\u0626\u0648\u0644 \u062F\u06CC\u06AF\u0631\u06CC \u0648\u0627\u06AF\u0630\u0627\u0631 \u0634\u062F\u0647 \u0627\u0633\u062A.",
    outside_scope: "\u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647 \u062E\u0627\u0631\u062C \u0627\u0632 \u0645\u062D\u062F\u0648\u062F\u0647 \u062F\u0633\u062A\u0631\u0633\u06CC \u0634\u0645\u0627\u0633\u062A.",
    stage_not_authorized: "\u062B\u0628\u062A \u0627\u06CC\u0646 \u062A\u063A\u06CC\u06CC\u0631 \u062F\u0631 \u0645\u0631\u062D\u0644\u0647 \u0641\u0639\u0644\u06CC \u06AF\u0631\u062F\u0634 \u06A9\u0627\u0631 \u0645\u062C\u0627\u0632 \u0646\u06CC\u0633\u062A.",
    source_owned_value_read_only: "\u0645\u0642\u062F\u0627\u0631 \u062E\u0648\u062F\u06A9\u0627\u0631 \u0648 \u0645\u062D\u0627\u0641\u0638\u062A\u200C\u0634\u062F\u0647 \u0642\u0627\u0628\u0644 \u0648\u06CC\u0631\u0627\u06CC\u0634 \u062F\u0633\u062A\u06CC \u0646\u06CC\u0633\u062A.",
    finalized_record_locked: "\u067E\u0631\u0648\u0646\u062F\u0647 \u0646\u0647\u0627\u06CC\u06CC \u06CC\u0627 \u0642\u0641\u0644\u200C\u0634\u062F\u0647 \u0642\u0627\u0628\u0644 \u0648\u06CC\u0631\u0627\u06CC\u0634 \u0646\u06CC\u0633\u062A.",
    score_limit_exceeded: "\u0646\u0645\u0631\u0647 \u0648\u0627\u0631\u062F\u0634\u062F\u0647 \u062E\u0627\u0631\u062C \u0627\u0632 \u0628\u0627\u0632\u0647 \u0645\u062C\u0627\u0632 \u0627\u06CC\u0646 \u0645\u0639\u06CC\u0627\u0631 \u0627\u0633\u062A.",
    invalid_criterion_configuration: "\u0645\u062D\u062F\u0648\u062F\u0647 \u0646\u0645\u0631\u0647\u060C \u0647\u062F\u0641 \u06CC\u0627 \u062A\u0631\u062A\u06CC\u0628 \u0622\u0633\u062A\u0627\u0646\u0647\u200C\u0647\u0627\u06CC \u0627\u06CC\u0646 \u0645\u0639\u06CC\u0627\u0631 \u0645\u0639\u062A\u0628\u0631 \u0646\u06CC\u0633\u062A.",
    permission_denied: "\u0628\u0631\u0627\u06CC \u062B\u0628\u062A \u0627\u06CC\u0646 \u062A\u063A\u06CC\u06CC\u0631 \u0645\u062C\u0648\u0632 \u06A9\u0627\u0641\u06CC \u0648\u062C\u0648\u062F \u0646\u062F\u0627\u0631\u062F.",
    kasra_import_not_authorized: "\u0645\u062C\u0648\u0632 \u062F\u0631\u0648\u0646\u200C\u0631\u06CC\u0632\u06CC \u06A9\u0633\u0631\u06CC \u0628\u0631\u0627\u06CC \u0627\u06CC\u0646 \u06A9\u0627\u0631\u0645\u0646\u062F \u06CC\u0627 \u0645\u062D\u062F\u0648\u062F\u0647 \u0648\u062C\u0648\u062F \u0646\u062F\u0627\u0631\u062F.",
    mis_import_not_authorized: "\u0645\u062C\u0648\u0632 \u062F\u0631\u0648\u0646\u200C\u0631\u06CC\u0632\u06CC MIS \u0628\u0631\u0627\u06CC \u0627\u06CC\u0646 \u06A9\u0627\u0631\u0645\u0646\u062F \u06CC\u0627 \u0645\u062D\u062F\u0648\u062F\u0647 \u0648\u062C\u0648\u062F \u0646\u062F\u0627\u0631\u062F.",
    employee_import_not_authorized: "\u0645\u062C\u0648\u0632 \u062F\u0631\u0648\u0646\u200C\u0631\u06CC\u0632\u06CC \u0627\u0637\u0644\u0627\u0639\u0627\u062A \u067E\u0631\u0633\u0646\u0644\u06CC \u0628\u0631\u0627\u06CC \u0627\u06CC\u0646 \u06A9\u0627\u0631\u0628\u0631 \u06CC\u0627 \u0645\u062D\u062F\u0648\u062F\u0647 \u0648\u062C\u0648\u062F \u0646\u062F\u0627\u0631\u062F.",
    criteria_import_not_authorized: "\u0645\u062C\u0648\u0632 \u062F\u0631\u0648\u0646\u200C\u0631\u06CC\u0632\u06CC \u0645\u0639\u06CC\u0627\u0631\u0647\u0627 \u0628\u0631\u0627\u06CC \u0627\u06CC\u0646 \u06A9\u0627\u0631\u0628\u0631 \u0648\u062C\u0648\u062F \u0646\u062F\u0627\u0631\u062F.",
    source_import_invalid: "\u062F\u0627\u062F\u0647 \u062F\u0631\u0648\u0646\u200C\u0631\u06CC\u0632\u06CC \u0628\u0627 \u0645\u0646\u0628\u0639\u060C \u062F\u0648\u0631\u0647 \u06CC\u0627 \u0645\u0639\u06CC\u0627\u0631 \u0645\u062C\u0627\u0632 \u062A\u0637\u0628\u06CC\u0642 \u0646\u062F\u0627\u0631\u062F.",
    missing_required_input: "\u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0631\u0627\u06CC \u0646\u0647\u0627\u06CC\u06CC\u200C\u0633\u0627\u0632\u06CC \u062F\u0627\u062F\u0647\u200C\u0647\u0627\u06CC \u0644\u0627\u0632\u0645 \u0631\u0627 \u0646\u062F\u0627\u0631\u062F."
  };
  return jsonResponse({
    error: denial.reason === "missing_required_input" && denial.missingRequirements?.length ? `${messages[denial.reason]} ${denial.missingRequirements.join(" ")}` : messages[denial.reason],
    code: denial.reason === "invalid_criterion_configuration" ? "criterion_configuration_invalid" : ["kasra_import_not_authorized", "mis_import_not_authorized", "employee_import_not_authorized", "criteria_import_not_authorized", "source_import_invalid"].includes(denial.reason) ? denial.reason : "evaluation_write_denied",
    reason: denial.reason,
    ...denial.missingRequirements ? { missingRequirements: denial.missingRequirements } : {},
    ...denial.recordId ? { recordId: denial.recordId } : {},
    retryable: false
  }, 403);
}
__name(safeWriteDenialResponse, "safeWriteDenialResponse");
function safeAdminMasterDataChanges(current, changes) {
  if ("pe_archived_evaluations" in changes) {
    const before = Array.isArray(current.pe_archived_evaluations) ? current.pe_archived_evaluations : [];
    const after = Array.isArray(changes.pe_archived_evaluations) ? changes.pe_archived_evaluations : [];
    const afterById = new Map(after.map((item) => [String(item.id), item]));
    if (before.some((item) => JSON.stringify(item) !== JSON.stringify(afterById.get(String(item.id))))) return false;
  }
  const existingEmployees = Array.isArray(current.pe_employees) ? current.pe_employees : [];
  const employees = Array.isArray(changes.pe_employees) ? changes.pe_employees : existingEmployees;
  const remainingEmployeeIds = new Set(employees.map((item) => item.id));
  const currentEvaluations = Array.isArray(current.pe_evaluations) ? current.pe_evaluations : [];
  const evaluations = Array.isArray(changes.pe_evaluations) ? changes.pe_evaluations : currentEvaluations;
  const archivedEvaluations = Array.isArray(current.pe_archived_evaluations) ? current.pe_archived_evaluations : [];
  for (const item of existingEmployees) {
    if (remainingEmployeeIds.has(item.id)) continue;
    if (getEmployeeDeletionBlockReason(item, employees, evaluations, archivedEvaluations)) return false;
  }
  const existingCriteria = Array.isArray(current.pe_criteria) ? current.pe_criteria : [];
  const criteria = Array.isArray(changes.pe_criteria) ? changes.pe_criteria : existingCriteria;
  const remainingCriterionIds = new Set(criteria.map((item) => item.id));
  const existingProfiles = Array.isArray(current.pe_profiles) ? current.pe_profiles : [];
  const profiles = Array.isArray(changes.pe_profiles) ? changes.pe_profiles : existingProfiles;
  for (const criterion of existingCriteria) {
    if (remainingCriterionIds.has(criterion.id)) continue;
    if (existingProfiles.some((profile) => profile.items?.some((item) => item.cid === criterion.id)) || currentEvaluations.some((evaluation) => evaluation.scores.some((score) => score.cid === criterion.id) || evaluation.retiredScores?.some((score) => score.cid === criterion.id)) || archivedEvaluations.some((evaluation) => evaluation.scores.some((score) => score.cid === criterion.id) || evaluation.retiredScores?.some((score) => score.cid === criterion.id))) return false;
  }
  const remainingProfileIds = new Set(profiles.map((item) => item.id));
  for (const profile of existingProfiles) {
    if (remainingProfileIds.has(profile.id)) continue;
    if (employees.some((employee) => employee.profileId === profile.id) || currentEvaluations.some((evaluation) => evaluation.profileId === profile.id) || archivedEvaluations.some((evaluation) => evaluation.profileId === profile.id)) return false;
  }
  return true;
}
__name(safeAdminMasterDataChanges, "safeAdminMasterDataChanges");
function validateMasterDataImport(current, changes, session, sourceImport) {
  const key = sourceImport.importType === "EMPLOYEE" ? "pe_employees" : "pe_criteria";
  if (Object.keys(changes).some((name) => name !== key && name !== "pe_notifications")) return false;
  const actor = getActor(current, session);
  if (!actor) return false;
  const type = sourceImport.importType === "EMPLOYEE" ? "employee" : "criteria";
  if (!canImport(actor, type, void 0, getPermissionPolicy(current)).allowed) return false;
  if (sourceImport.importType === "CRITERIA") {
    const criteria = changes.pe_criteria;
    if (!Array.isArray(criteria) || !criteria.every(validCriterionScoringConfiguration)) return false;
    const ids = /* @__PURE__ */ new Set();
    const codes = /* @__PURE__ */ new Set();
    for (const criterion of criteria) {
      const code = String(criterion.code || "").trim().toLocaleUpperCase();
      if (!criterion.id || !code || !String(criterion.name || "").trim() || typeof criterion.def !== "string" || !["K", "Q", "B", "S", "L"].includes(criterion.cat) || criterion.scoringSource !== void 0 && !["supervisor", "mis", "kasra", "system", "multi_source"].includes(criterion.scoringSource) || ids.has(criterion.id) || codes.has(code)) return false;
      ids.add(criterion.id);
      codes.add(code);
    }
    return safeAdminMasterDataChanges(current, changes);
  }
  const incoming = changes.pe_employees;
  if (!Array.isArray(incoming)) return false;
  const existingEmployees = getEmployees(current);
  const existingById = new Map(existingEmployees.map((employee) => [employee.id, employee]));
  const validProfileIds = new Set(getProfiles(current).map((profile) => profile.id));
  const incomingIds = /* @__PURE__ */ new Set();
  const allEmployeeIds = /* @__PURE__ */ new Set([...existingEmployees.map((item) => item.id), ...incoming.map((item) => item?.id)]);
  const codeOwners = /* @__PURE__ */ new Map();
  const usernameOwners = /* @__PURE__ */ new Map();
  for (const existing of existingEmployees) {
    const code = normalizePersonnelCode(existing.code);
    if (code) codeOwners.set(code, existing.id);
    const username = String(existing.username || "").trim().toLocaleLowerCase();
    if (username) usernameOwners.set(username, existing.id);
  }
  for (const employee of incoming) {
    if (employee?.employmentStatus !== void 0 && !["active", "inactive", "unknown"].includes(employee.employmentStatus)) return false;
    if (!employee || typeof employee.id !== "string" || !employee.id || incomingIds.has(employee.id) || typeof employee.code !== "string" || !normalizePersonnelCode(employee.code) || typeof employee.username !== "string" || !employee.username.trim() || typeof employee.name !== "string" || !employee.name.trim() || typeof employee.unit !== "string" || typeof employee.profileId !== "string" || !validProfileIds.has(employee.profileId) || !["admin", "supervisor", "employee"].includes(employee.role)) return false;
    incomingIds.add(employee.id);
    const old = existingById.get(employee.id);
    if (employee.personnelEffectiveDate !== old?.personnelEffectiveDate && employee.personnelEffectiveDate !== void 0) {
      const incomingDate = parseBusinessDate(employee.personnelEffectiveDate);
      const previousDate = old?.personnelEffectiveDate ? parseBusinessDate(old.personnelEffectiveDate) : void 0;
      if (!incomingDate || previousDate && incomingDate < previousDate) return false;
    }
    const changed = !old || JSON.stringify(old) !== JSON.stringify(employee);
    if (!changed) continue;
    const permission = canImport(actor, "employee", old || employee, getPermissionPolicy(current));
    if (!permission.allowed || !permission.scope || !employeeWithinScope(actor, employee, permission.scope)) return false;
    const code = normalizePersonnelCode(employee.code);
    const codeOwner = codeOwners.get(code);
    if (codeOwner && codeOwner !== employee.id) return false;
    codeOwners.set(code, employee.id);
    const username = employee.username.trim().toLocaleLowerCase();
    const usernameOwner = usernameOwners.get(username);
    if (usernameOwner && usernameOwner !== employee.id) return false;
    usernameOwners.set(username, employee.id);
    for (const relationId of [employee.supervisorId, employee.peerReviewerId, employee.calibrationLeadId, employee.approverId, employee.hrPartnerId, employee.hseReviewerId]) {
      if (relationId && (!allEmployeeIds.has(relationId) || relationId === employee.id)) return false;
    }
    if (actor.role !== "admin") {
      if (old) {
        for (const field of ["role", "username", "supervisorId", "peerReviewerId", "calibrationLeadId", "approverId", "hrPartnerId", "hseReviewerId"]) {
          if ((old[field] ?? "") !== (employee[field] ?? "")) return false;
        }
      } else if (employee.role !== "employee" || employee.username !== `user_${code.toLocaleLowerCase()}` || employee.supervisorId && employee.supervisorId !== actor.id || employee.peerReviewerId || employee.calibrationLeadId || employee.approverId || employee.hrPartnerId || employee.hseReviewerId) return false;
    }
  }
  const merged = new Map(existingEmployees.map((employee) => [employee.id, employee]));
  incoming.forEach((employee) => merged.set(employee.id, employee));
  const finalEmployees = Array.from(merged.values());
  return safeAdminMasterDataChanges(current, { ...changes, pe_employees: finalEmployees });
}
__name(validateMasterDataImport, "validateMasterDataImport");
function scopedState(state, session) {
  if (session.role === "admin") return { ...state, pe_notifications: getNotifications(state).filter((item) => item.recipientId === session.id) };
  const employees = Array.isArray(state.pe_employees) ? state.pe_employees : [];
  const allowedIds = allowedEmployeeIds(state, session);
  const policy = getPermissionPolicy(state);
  const analyticsActor = getActor(state, session);
  const analyticsEmployees = getEmployees(state);
  const analyticsAllowedIds = new Set(
    analyticsActor ? analyticsEmployees.filter((employee) => authorize(analyticsActor, "analytics", "view", employee, policy).allowed).map((employee) => employee.id) : []
  );
  const result = { ...state };
  const violationEmployeeIds = new Set(analyticsEmployees.filter((employee) => analyticsActor && ["view", "create", "import", "edit", "submit", "approve"].some((capability) => authorize(analyticsActor, "violations", capability, employee, policy).allowed)).map((employee) => employee.id));
  result.pe_violations = (state.pe_violations || []).filter((record) => {
    const subject = analyticsEmployees.find((e) => e.id === record.employeeId);
    return record.employeeId === session.id || Boolean(subject && analyticsActor && authorize(analyticsActor, "violations", "view", subject, policy).allowed);
  });
  delete result.pe_violation_operations;
  for (const key of ["pe_kickidler_live", "pe_kickidler_records", "pe_kickidler_violations"]) {
    if (!Array.isArray(state[key])) continue;
    result[key] = state[key].filter((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return false;
      const empId = value.empId;
      return typeof empId === "string" && analyticsAllowedIds.has(empId);
    });
  }
  if (Array.isArray(state.pe_evaluations)) {
    const evaluations = state.pe_evaluations;
    result.pe_evaluations = evaluations.filter((item) => canAccessEvaluation(item, state, session, allowedIds));
    const assignedEmployeeIds = new Set(evaluations.filter(
      (item) => canAccessEvaluation(item, state, session, allowedIds)
    ).map((item) => item.empId));
    allowedIds.forEach((id) => assignedEmployeeIds.add(id));
    getDelegations(state).filter((item) => item.delegatorId === session.id || item.delegateId === session.id).forEach((item) => {
      assignedEmployeeIds.add(item.delegatorId);
      assignedEmployeeIds.add(item.delegateId);
    });
    result.pe_employees = employees.filter((employee) => assignedEmployeeIds.has(employee.id));
  }
  if (!Array.isArray(state.pe_evaluations)) {
    getDelegations(state).filter((item) => item.delegatorId === session.id || item.delegateId === session.id).forEach((item) => {
      allowedIds.add(item.delegatorId);
      allowedIds.add(item.delegateId);
    });
    result.pe_employees = employees.filter((employee) => allowedIds.has(employee.id));
  }
  result.pe_delegations = getDelegations(state).filter((item) => item.delegatorId === session.id || item.delegateId === session.id);
  if (violationEmployeeIds.size) {
    const visibleIds = new Set((result.pe_employees || []).map((e) => e.id));
    result.pe_employees = [...result.pe_employees || [], ...analyticsEmployees.filter((e) => violationEmployeeIds.has(e.id) && !visibleIds.has(e.id))];
  }
  result.pe_notifications = getNotifications(state).filter((item) => item.recipientId === session.id);
  result.pe_granular_permissions = {
    version: 1,
    roles: { [session.role]: policy.roles?.[session.role] },
    users: policy.users?.[session.id] ? { [session.id]: policy.users[session.id] } : {},
    workflowCeilings: { [session.role]: policy.workflowCeilings?.[session.role] },
    userWorkflowCeilings: policy.userWorkflowCeilings?.[session.id] ? { [session.id]: policy.userWorkflowCeilings[session.id] } : {},
    workflowStageCapabilities: { [session.role]: policy.workflowStageCapabilities?.[session.role] },
    userWorkflowStageCapabilities: policy.userWorkflowStageCapabilities?.[session.id] ? { [session.id]: policy.userWorkflowStageCapabilities[session.id] } : {}
  };
  for (const key of [
    "pe_reward_config",
    "pe_reward_batch_history",
    "pe_system_logs",
    "pe_audit_logs",
    "pe_role_permissions",
    "pe_user_custom_permissions",
    "pe_locked_users"
  ]) delete result[key];
  const contacts = /* @__PURE__ */ new Map();
  for (const evaluation of result.pe_evaluations || []) {
    const employee = employees.find((person) => person.id === evaluation.empId);
    for (const stage of ["self_review", "supervisor_review", "peer_review", "calibration_review", "hr_approval", "hse_review", "feedback_meeting", "appealed"]) {
      const owner = resolveWorkflowAssignee(stage, employee, employees);
      if (employees.some((person) => person.id === owner.id)) contacts.set(owner.id, { id: owner.id, name: owner.name, role: owner.role, code: owner.code, unit: owner.unit });
    }
  }
  return { ...sanitizeCloudState(result), pe_workflow_contacts: [...contacts.values()] };
}
__name(scopedState, "scopedState");
function mergeAuthorizedState(current, changes, session, sourceImport) {
  const next = { ...current };
  if (sourceImport && isMasterDataSourceImportContext(sourceImport)) {
    const audit = Array.isArray(current.pe_audit_logs) ? [...current.pe_audit_logs] : [];
    const timestamp = (/* @__PURE__ */ new Date()).toISOString();
    if (sourceImport.importType === "EMPLOYEE" && Array.isArray(changes.pe_employees)) {
      const oldEmployees = getEmployees(current);
      const incoming = changes.pe_employees;
      const byId = new Map(oldEmployees.map((employee) => [employee.id, employee]));
      incoming.forEach((employee) => byId.set(employee.id, employee));
      const finalEmployees = session.role === "admin" ? incoming : Array.from(byId.values());
      const oldById = new Map(oldEmployees.map((employee) => [employee.id, employee]));
      const changed = finalEmployees.filter((employee) => JSON.stringify(oldById.get(employee.id)) !== JSON.stringify(employee));
      const removed = oldEmployees.filter((employee) => !finalEmployees.some((nextEmployee) => nextEmployee.id === employee.id));
      next.pe_employees = finalEmployees;
      changed.forEach((employee) => audit.unshift({
        id: `audit:employee_import:${sourceImport.operationId}:${employee.id}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: oldById.has(employee.id) ? "employee_import_updated" : "employee_import_created",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        target: employee.id,
        result: "accepted"
      }));
      removed.forEach((employee) => audit.unshift({
        id: `audit:employee_import_removed:${sourceImport.operationId}:${employee.id}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: "employee_import_removed",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        target: employee.id,
        result: "accepted"
      }));
      audit.unshift({
        id: `audit:source_import:${sourceImport.operationId}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: "source_import_completed",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        affectedRecordCount: changed.length,
        createdCount: changed.filter((employee) => !oldById.has(employee.id)).length,
        updatedCount: changed.filter((employee) => oldById.has(employee.id)).length,
        removedCount: removed.length,
        result: "accepted"
      });
    } else if (sourceImport.importType === "CRITERIA" && Array.isArray(changes.pe_criteria)) {
      const oldCriteria = Array.isArray(current.pe_criteria) ? current.pe_criteria : [];
      const newCriteria = changes.pe_criteria;
      const oldById = new Map(oldCriteria.map((criterion) => [criterion.id, criterion]));
      const newById = new Map(newCriteria.map((criterion) => [criterion.id, criterion]));
      const changed = newCriteria.filter((criterion) => JSON.stringify(oldById.get(criterion.id)) !== JSON.stringify(criterion));
      const removed = oldCriteria.filter((criterion) => !newById.has(criterion.id));
      next.pe_criteria = newCriteria;
      changed.forEach((criterion) => audit.unshift({
        id: `audit:criteria_import:${sourceImport.operationId}:${criterion.id}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: oldById.has(criterion.id) ? "criteria_import_updated" : "criteria_import_created",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        target: criterion.id,
        result: "accepted"
      }));
      removed.forEach((criterion) => audit.unshift({
        id: `audit:criteria_import_removed:${sourceImport.operationId}:${criterion.id}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: "criteria_import_removed",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        target: criterion.id,
        result: "accepted"
      }));
      audit.unshift({
        id: `audit:source_import:${sourceImport.operationId}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: "source_import_completed",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        affectedRecordCount: changed.length,
        createdCount: changed.filter((criterion) => !oldById.has(criterion.id)).length,
        updatedCount: changed.filter((criterion) => oldById.has(criterion.id)).length,
        removedCount: removed.length,
        result: "accepted"
      });
    }
    next.pe_audit_logs = audit;
  }
  if (Array.isArray(changes.pe_evaluations)) {
    const currentEvaluations = Array.isArray(current.pe_evaluations) ? current.pe_evaluations : [];
    const currentById = new Map(currentEvaluations.map((item) => [item.id, item]));
    const incoming = changes.pe_evaluations.filter((item) => {
      const existing = currentById.get(item?.id);
      return existing !== item && (!existing || JSON.stringify(existing) !== JSON.stringify(item));
    });
    const byId = new Map(currentEvaluations.map((item) => [item.id, item]));
    let notifications = [...getNotifications(current)];
    const notificationEventKeys = new Set(notifications.map((item) => item.eventKey));
    const employeeIds = new Set(getEmployees(current).map((employee) => employee.id));
    const audit = [];
    if (session.role === "admin" && !(sourceImport && isProtectedSourceImportContext(sourceImport))) {
      const retainedIds = new Set(changes.pe_evaluations.map((item) => item.id));
      for (const existing of currentEvaluations) {
        if (retainedIds.has(existing.id)) continue;
        byId.delete(existing.id);
        audit.unshift({ id: `audit:evaluation_deleted:${existing.id}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: "evaluation_deleted", target: existing.id, previousState: { stage: existing.stage, status: existing.status, currentAssigneeId: existing.currentAssigneeId }, resultingState: null, result: "accepted" });
      }
    }
    incoming.forEach((item) => {
      const existing = currentById.get(item.id);
      const newestLog = item.history?.[0] || void 0;
      const log = newestLog && (!existing || newestLog.id !== existing.history?.[0]?.id) ? newestLog : void 0;
      if (log && existing) {
        log.actorId = session.id;
        log.actorName = session.name;
        log.actorRole = session.role;
        log.timestamp = (/* @__PURE__ */ new Date()).toISOString();
        const resolutionTime = (/* @__PURE__ */ new Date()).toISOString();
        const resolutionReason = item.status === "locked" || item.stage === "completed" ? "task_completed" : existing.currentAssigneeId !== item.currentAssigneeId ? "owner_changed" : "workflow_transitioned";
        notifications = notifications.map((notice) => notice.evaluationId === item.id && !notice.resolvedAt ? { ...notice, resolvedAt: resolutionTime, resolvedReason: resolutionReason } : notice);
      }
      byId.set(item.id, item);
      const notification = notificationFor(item, session, log, !existing, employeeIds);
      if (notification && !notificationEventKeys.has(notification.eventKey)) {
        notifications.push(notification);
        notificationEventKeys.add(notification.eventKey);
      }
      const before = existing ? evaluationAuditState(existing) : null;
      const after = evaluationAuditState(item);
      const scoreChanges = evaluationScoreChanges(existing, item);
      if (scoreChanges.length) {
        if (before) before.scoreChanges = scoreChanges.map((change) => ({ cid: change.cid, value: change.previous.value }));
        after.scoreChanges = scoreChanges.map((change) => ({ cid: change.cid, value: change.resulting.value }));
      }
      audit.unshift({ id: `audit:${item.id}:${log?.id || (existing ? `edit:${crypto.randomUUID()}` : "created")}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: log?.action || (existing ? scoreChanges.length && item.bulkOperationId ? "bulk_score" : "evaluation_updated" : "evaluation_started"), target: item.id, bulkOperationId: item.bulkOperationId, previousState: before, resultingState: after, result: "accepted" });
    });
    if (sourceImport && isProtectedSourceImportContext(sourceImport)) {
      const importedEvaluations = incoming.filter((item) => {
        const before = currentById.get(item.id);
        const updated = item;
        return Boolean(before && before.empId === updated.empId && updated.scores.some((score) => before.scores.some((previous) => previous.cid === score.cid && JSON.stringify(previous) !== JSON.stringify(score))));
      });
      const timestamp = (/* @__PURE__ */ new Date()).toISOString();
      const employeeIds2 = new Set(importedEvaluations.map((item) => item.empId));
      const scoreAudits = [];
      for (const updated of importedEvaluations) {
        const before = currentById.get(updated.id);
        if (!before) continue;
        const previousScores = new Map(before.scores.map((score) => [score.cid, score]));
        for (const nextScore of updated.scores) {
          const previousScore = previousScores.get(nextScore.cid);
          if (!previousScore || JSON.stringify(previousScore) === JSON.stringify(nextScore)) continue;
          scoreAudits.push({
            id: `audit:source_import_score:${sourceImport.operationId}:${updated.id}:${nextScore.cid}`,
            timestamp,
            actorId: session.id,
            actorName: session.name,
            actorRole: session.role,
            action: "source_import_score_updated",
            importType: sourceImport.importType,
            operationId: sourceImport.operationId,
            evaluationPeriodId: sourceImport.evaluationPeriodId,
            employeeId: updated.empId,
            evaluationId: updated.id,
            criterionId: nextScore.cid,
            previousValue: previousScore.value,
            newValue: nextScore.value,
            previousRawMetricValue: previousScore.rawMetricValue ?? null,
            rawMetricValue: nextScore.rawMetricValue ?? null,
            provenance: { sourceType: nextScore.sourceType, rawMetricLabel: nextScore.rawMetricLabel ?? null },
            result: "accepted"
          });
        }
      }
      audit.unshift({
        id: `audit:source_import:${sourceImport.operationId}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: "source_import_completed",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        evaluationPeriodId: sourceImport.evaluationPeriodId,
        rowsRead: Math.max(importedEvaluations.length, sourceImport.rowsRead ?? importedEvaluations.length),
        acceptedRows: importedEvaluations.length,
        rejectedRows: Math.max(0, Math.max(importedEvaluations.length, sourceImport.rowsRead ?? importedEvaluations.length) - importedEvaluations.length),
        affectedEvaluationCount: importedEvaluations.length,
        affectedEmployeeCount: employeeIds2.size,
        result: "accepted"
      });
      audit.unshift(...scoreAudits);
    } else if (sourceImport?.importType === "FILE_IMPORT") {
      const importedEvaluations = incoming.filter((item) => {
        const before = currentById.get(item.id);
        return !before || JSON.stringify(before) !== JSON.stringify(item);
      });
      const timestamp = (/* @__PURE__ */ new Date()).toISOString();
      const affectedEmployees = new Set(importedEvaluations.map((item) => item.empId));
      const rowsRead = Math.max(importedEvaluations.length, sourceImport.rowsRead ?? importedEvaluations.length);
      audit.unshift({
        id: `audit:source_import:${sourceImport.operationId}`,
        timestamp,
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: "source_import_completed",
        importType: sourceImport.importType,
        operationId: sourceImport.operationId,
        evaluationPeriodId: sourceImport.evaluationPeriodId,
        rowsRead,
        acceptedRows: importedEvaluations.length,
        rejectedRows: Math.max(0, rowsRead - importedEvaluations.length),
        affectedEvaluationCount: importedEvaluations.length,
        affectedEmployeeCount: affectedEmployees.size,
        result: "accepted"
      });
    }
    next.pe_evaluations = Array.from(byId.values());
    next.pe_notifications = notifications.slice(0, 1e4);
    next.pe_audit_logs = [...audit, ...Array.isArray(current.pe_audit_logs) ? current.pe_audit_logs : []];
  }
  if (Array.isArray(changes.pe_delegations)) {
    const byId = new Map(getDelegations(current).map((item) => [item.id, item]));
    const notices = [...getNotifications(next)];
    const noticeEventKeys = new Set(notices.map((item) => item.eventKey));
    const audit = Array.isArray(next.pe_audit_logs) ? [...next.pe_audit_logs] : [];
    changes.pe_delegations.forEach((item) => {
      const previous = byId.get(item.id);
      if (previous && JSON.stringify(previous) === JSON.stringify(item)) return;
      byId.set(item.id, item);
      if (!previous || previous.status !== "revoked" && item.status === "revoked") {
        const isRevoked = item.status === "revoked";
        const eventKey = `delegation:${item.id}:${isRevoked ? "revoked" : "created"}`;
        const recipientId = item.delegateId;
        if (!noticeEventKeys.has(eventKey)) {
          notices.push({
            id: `notification:${eventKey}`,
            eventKey,
            recipientId,
            eventType: isRevoked ? "delegation_revoked" : "delegation_created",
            title: isRevoked ? "\u062A\u0641\u0648\u06CC\u0636 \u0627\u062E\u062A\u06CC\u0627\u0631 \u0644\u063A\u0648 \u0634\u062F" : "\u0627\u062E\u062A\u06CC\u0627\u0631 \u062C\u062F\u06CC\u062F \u0628\u0647 \u0634\u0645\u0627 \u0648\u0627\u06AF\u0630\u0627\u0631 \u0634\u062F",
            message: isRevoked ? "\u062F\u0633\u062A\u0631\u0633\u06CC \u062A\u0641\u0648\u06CC\u0636\u200C\u0634\u062F\u0647 \u0628\u0631\u0627\u06CC \u0627\u06CC\u0646 \u067E\u0631\u0648\u0646\u062F\u0647/\u0645\u062D\u062F\u0648\u062F\u0647 \u0644\u063A\u0648 \u0634\u062F\u0647 \u0627\u0633\u062A." : "\u06CC\u06A9 \u0627\u062E\u062A\u06CC\u0627\u0631 \u0645\u0648\u0642\u062A \u0628\u0631\u0627\u06CC \u067E\u06CC\u06AF\u06CC\u0631\u06CC \u067E\u0631\u0648\u0646\u062F\u0647 \u0628\u0647 \u0634\u0645\u0627 \u0648\u0627\u06AF\u0630\u0627\u0631 \u0634\u062F\u0647 \u0627\u0633\u062A.",
            targetTab: "workflow",
            actorId: session.id,
            createdAt: (/* @__PURE__ */ new Date()).toISOString()
          });
          noticeEventKeys.add(eventKey);
        }
        audit.unshift({ id: `audit:delegation:${item.id}:${isRevoked ? "revoked" : "created"}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: isRevoked ? "delegation_revoked" : "delegation_created", target: item.id, previousState: previous || null, resultingState: item, result: "accepted" });
      }
    });
    next.pe_delegations = Array.from(byId.values());
    next.pe_notifications = notices.slice(0, 1e4);
    next.pe_audit_logs = audit;
  }
  if (Array.isArray(changes.pe_notifications)) {
    const byId = new Map(getNotifications(current).map((item) => [item.id, item]));
    changes.pe_notifications.forEach((item) => {
      const existing = byId.get(item.id);
      if (existing?.recipientId === session.id && !existing.readAt && item.readAt) byId.set(item.id, { ...existing, readAt: item.readAt });
    });
    next.pe_notifications = Array.from(byId.values());
  }
  for (const key of ["pe_lattice_okrs", "pe_lattice_one_on_ones", "pe_lattice_kudos", "pe_tickets"]) {
    if (key in changes) next[key] = changes[key];
  }
  if (session.role === "admin") {
    for (const [key, value] of Object.entries(changes)) {
      if (key === "pe_evaluations" || key === "pe_notifications" || key === "pe_audit_logs") continue;
      next[key] = value;
    }
    const masterKeys = ["pe_employees", "pe_criteria", "pe_profiles"];
    let audit = Array.isArray(next.pe_audit_logs) ? next.pe_audit_logs : [];
    if (masterKeys.some((key) => key in changes)) audit = [...audit];
    for (const masterKey of masterKeys) {
      if (!(masterKey in changes) || JSON.stringify(changes[masterKey]) === JSON.stringify(current[masterKey])) continue;
      const previousRows = Array.isArray(current[masterKey]) ? current[masterKey] : [];
      const nextRows = Array.isArray(changes[masterKey]) ? changes[masterKey] : [];
      const oldById = new Map(previousRows.map((item) => [String(item.id), item]));
      const newById = new Map(nextRows.map((item) => [String(item.id), item]));
      for (const [id, item] of oldById) if (!newById.has(id)) audit.unshift({ id: `audit:delete:${masterKey}:${id}:${Date.now()}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: `${masterKey}_deleted`, target: id, previousState: item, resultingState: null, result: "accepted" });
      for (const [id, item] of newById) {
        const old = oldById.get(id);
        if (!old) audit.unshift({ id: `audit:create:${masterKey}:${id}:${Date.now()}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: `${masterKey}_created`, target: id, previousState: null, resultingState: item, result: "accepted" });
        else if (JSON.stringify(old) !== JSON.stringify(item)) audit.unshift({ id: `audit:edit:${masterKey}:${id}:${Date.now()}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: `${masterKey}_edited`, target: id, previousState: old, resultingState: item, result: "accepted" });
      }
    }
    next.pe_audit_logs = audit;
    const auditedPolicyKeys = ["pe_granular_permissions", "pe_role_permissions", "pe_user_custom_permissions"];
    const changedPolicyKeys = auditedPolicyKeys.filter((key) => key in changes && JSON.stringify(changes[key]) !== JSON.stringify(current[key]));
    if (changedPolicyKeys.length) {
      const policyAudit = Array.isArray(next.pe_audit_logs) ? [...next.pe_audit_logs] : [];
      for (const changedPolicyKey of changedPolicyKeys) policyAudit.unshift({ id: `audit:policy:${Date.now()}:${session.id}:${changedPolicyKey}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: "permission_policy_updated", target: changedPolicyKey, previousState: current[changedPolicyKey] ?? null, resultingState: changes[changedPolicyKey], result: "accepted" });
      next.pe_audit_logs = policyAudit;
    }
    if ("pe_workflow_sla" in changes && JSON.stringify(changes.pe_workflow_sla) !== JSON.stringify(current.pe_workflow_sla)) {
      const settingAudit = Array.isArray(next.pe_audit_logs) ? [...next.pe_audit_logs] : [];
      settingAudit.unshift({
        id: `audit:workflow_sla:${crypto.randomUUID()}`,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        actorId: session.id,
        actorName: session.name,
        actorRole: session.role,
        action: "workflow_sla_updated",
        target: "pe_workflow_sla",
        previousState: current.pe_workflow_sla ?? null,
        resultingState: changes.pe_workflow_sla,
        result: "accepted"
      });
      next.pe_audit_logs = settingAudit;
    }
    if ("pe_active_period" in changes && JSON.stringify(changes.pe_active_period) !== JSON.stringify(current.pe_active_period)) {
      const audit2 = Array.isArray(next.pe_audit_logs) ? [...next.pe_audit_logs] : [];
      audit2.unshift({ id: `audit:period:${Date.now()}:${session.id}`, timestamp: (/* @__PURE__ */ new Date()).toISOString(), actorId: session.id, actorName: session.name, actorRole: session.role, action: "evaluation_period_started", target: String(changes.pe_active_period), previousState: current.pe_active_period ?? null, resultingState: changes.pe_active_period, result: "accepted" });
      next.pe_audit_logs = audit2;
    }
  }
  return sanitizeCloudState(next);
}
__name(mergeAuthorizedState, "mergeAuthorizedState");
function resolveTransitionOwners(current, changes, session) {
  if (!Array.isArray(changes.pe_evaluations)) return changes;
  const employees = getEmployees(current);
  const existingById = new Map((Array.isArray(current.pe_evaluations) ? current.pe_evaluations : []).map((item) => [item.id, item]));
  return {
    ...changes,
    pe_evaluations: changes.pe_evaluations.map((incoming) => {
      const existing = existingById.get(incoming.id);
      const newest = incoming.history?.[0];
      if (existing && newest?.action === "route_hse" && newest.id !== existing.history?.[0]?.id) {
        const employee = employees.find((item) => item.id === existing.empId);
        const reviewer = employee?.hseReviewerId ? employees.find((item) => item.id === employee.hseReviewerId) : void 0;
        const reason = typeof incoming.hseReviewContext?.reason === "string" ? incoming.hseReviewContext.reason.trim().slice(0, 1e3) : "";
        return {
          ...incoming,
          status: existing.status,
          currentAssigneeId: reviewer?.id,
          currentAssigneeName: reviewer?.name,
          currentAssigneeRole: reviewer?.role,
          hseReviewContext: reviewer ? {
            requestedFromStage: existing.stage || "self_review",
            returnStage: existing.stage || "self_review",
            requestedById: session.id,
            requestedAt: (/* @__PURE__ */ new Date()).toISOString(),
            hseReviewerId: reviewer.id,
            reason,
            returnAssigneeId: existing.currentAssigneeId || "",
            returnAssigneeName: existing.currentAssigneeName || "",
            returnAssigneeRole: existing.currentAssigneeRole || "admin"
          } : incoming.hseReviewContext
        };
      }
      if (existing && newest?.action === "complete_hse_review" && newest.id !== existing.history?.[0]?.id) {
        const prior = existing.hseReviewContext;
        const note = typeof incoming.hseReviewContext?.reviewNote === "string" ? incoming.hseReviewContext.reviewNote.trim().slice(0, 1e3) : "";
        return {
          ...incoming,
          status: existing.status,
          currentAssigneeId: prior?.returnAssigneeId,
          currentAssigneeName: prior?.returnAssigneeName,
          currentAssigneeRole: prior?.returnAssigneeRole,
          hseReviewContext: prior ? { ...prior, reviewNote: note || void 0, reviewedAt: (/* @__PURE__ */ new Date()).toISOString() } : incoming.hseReviewContext
        };
      }
      if (session.role === "admin") return incoming;
      if (!existing || !newest || newest.action === "reassign_assignee" || (existing.stage || "self_review") === (incoming.stage || "self_review")) return incoming;
      const assignee = resolveWorkflowAssignee(incoming.stage || "self_review", employees.find((item) => item.id === incoming.empId), employees);
      return { ...incoming, currentAssigneeId: assignee.id, currentAssigneeName: assignee.name, currentAssigneeRole: assignee.role };
    })
  };
}
__name(resolveTransitionOwners, "resolveTransitionOwners");
function responseEnvelope(state, meta, session, receipt, ignoredLogOperation) {
  const { __operation_receipts: _receipts, ...visibleState } = state;
  return jsonResponse({ storage: "sqlite-durable-object", protocolVersion: 2, state: scopedState(visibleState, session), ...meta, ...receipt ? { accepted: true, ...receipt } : {}, ...ignoredLogOperation ? { noMutation: true, ignoredKeys: ["pe_system_logs"], operationId: ignoredLogOperation } : {} });
}
__name(responseEnvelope, "responseEnvelope");
async function onRequestGet2(context) {
  const { env, data } = context;
  if (!data.session) return jsonResponse({ error: "Authentication required.", code: "authentication_required", reason: "authentication_required", retryable: false }, 401);
  try {
    const operationId = new URL(context.request.url).searchParams.get("operationId");
    const { state, meta } = await readState(env, operationId || void 0);
    if (operationId) {
      const found = env.TRANSACTION_STORE.receipt(operationId);
      const receipt = found?.actorId === data.session.id ? found : void 0;
      if (!receipt) return jsonResponse({ storage: "sqlite-durable-object", protocolVersion: 2, accepted: false, operationId, revision: meta.revision });
      const { __operation_receipts: _receipts, ...visibleState } = state;
      return jsonResponse({ storage: "sqlite-durable-object", protocolVersion: 2, accepted: true, operationId, payloadHash: receipt.payloadHash, acceptedRevision: receipt.acceptedRevision, state: scopedState(visibleState, data.session), ...meta });
    }
    return responseEnvelope(state, meta, data.session);
  } catch (error) {
    if (error instanceof StateStoreUnavailable) {
      await logStateStoreFailure(error, context, { requestBytes: 0, startedAt: Date.now(), retryCount: 0 });
      return jsonResponse({ error: "\u0630\u062E\u06CC\u0631\u0647\u200C\u06AF\u0627\u0647 \u0627\u0628\u0631\u06CC \u0645\u0648\u0642\u062A\u0627\u064B \u067E\u0627\u0633\u062E \u0646\u0645\u06CC\u200C\u062F\u0647\u062F.", code: error.code, reason: "kv_read_failed", retryable: true }, 503);
    }
    return jsonResponse({ error: "\u067E\u0631\u062F\u0627\u0632\u0634 \u062F\u0631\u062E\u0648\u0627\u0633\u062A \u062E\u0648\u0627\u0646\u062F\u0646 \u0648\u0636\u0639\u06CC\u062A \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062F.", code: "internal_server_error", reason: "internal_error", retryable: false }, 500);
  }
}
__name(onRequestGet2, "onRequestGet");
async function onRequestPost(context) {
  activeStateWrites += 1;
  try {
    return await writeState(context);
  } catch (error) {
    if (error instanceof StateStoreUnavailable) {
      await logStateStoreFailure(error, context, context.data.diagnostics || { requestBytes: 0, startedAt: Date.now(), retryCount: 0 });
      return jsonResponse({ error: "\u0630\u062E\u06CC\u0631\u0647 \u062A\u0631\u0627\u06A9\u0646\u0634\u06CC \u062A\u0623\u06CC\u06CC\u062F \u0646\u0634\u062F\u061B \u0646\u062A\u06CC\u062C\u0647 \u0631\u0627 \u0628\u0627 \u0647\u0645\u0627\u0646 \u0634\u0646\u0627\u0633\u0647 \u0639\u0645\u0644\u06CC\u0627\u062A \u0628\u0631\u0631\u0633\u06CC \u06A9\u0646\u06CC\u062F.", code: error.code, reason: "transaction_store_failed", retryable: false, operationId: error.operationId }, 503);
    }
    return jsonResponse({ error: "\u067E\u0631\u062F\u0627\u0632\u0634 \u0630\u062E\u06CC\u0631\u0647 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062F\u061B \u062A\u063A\u06CC\u06CC\u0631\u0627\u062A \u062D\u0641\u0638 \u0634\u062F\u0646\u062F.", code: "internal_server_error", retryable: false }, 500);
  } finally {
    activeStateWrites = Math.max(0, activeStateWrites - 1);
  }
}
__name(onRequestPost, "onRequestPost");
async function writeState({ request, env, data }) {
  if (!data.session) return jsonResponse({ error: "Authentication required.", code: "authentication_required", reason: "authentication_required", retryable: false }, 401);
  if (!request.headers.get("Content-Type")?.toLowerCase().includes("application/json")) {
    return jsonResponse({ error: "Content-Type must be application/json.", code: "content_type_unsupported", reason: "content_type_unsupported", retryable: false }, 415);
  }
  const text2 = await request.text();
  const requestBytes = new TextEncoder().encode(text2).byteLength;
  data.diagnostics = {
    requestBytes,
    startedAt: Date.now(),
    retryCount: Math.max(0, Number.parseInt(request.headers.get("X-Chalak-Retry-Count") || "0", 10) || 0)
  };
  if (requestBytes > 5e6) return jsonResponse({ error: "Payload is too large.", code: "payload_too_large", reason: "payload_too_large", retryable: false }, 413);
  let body;
  try {
    body = JSON.parse(text2);
  } catch {
    return jsonResponse({ error: "Invalid JSON payload.", code: "invalid_json", reason: "invalid_json", retryable: false }, 400);
  }
  if (body.sourceImport !== void 0 && !isSourceImportContext(body.sourceImport)) {
    return jsonResponse({ error: "Invalid protected import context.", code: "source_import_invalid", reason: "source_import_invalid", retryable: false }, 400);
  }
  const sourceImport = body.sourceImport;
  const operationId = body.operationId ?? sourceImport?.operationId;
  if (operationId !== void 0 && (typeof operationId !== "string" || !/^[a-zA-Z0-9:_-]{8,100}$/.test(operationId))) return jsonResponse({ error: "Invalid operation identifier.", code: "operation_id_invalid", reason: "operation_id_invalid", retryable: false }, 400);
  if (body.evaluationPatch !== void 0 && typeof body.evaluationPatch !== "boolean") return jsonResponse({ error: "Invalid changed-set mode.", code: "evaluation_patch_invalid", reason: "evaluation_patch_invalid", retryable: false }, 400);
  const changes = sanitizeCloudState(body.state === void 0 ? body : body.state);
  if (Object.keys(changes).length === 0) return jsonResponse({ error: "No synchronized changes were supplied.", code: "empty_changes", reason: "empty_changes", retryable: false }, 400);
  if (sourceImport && isProtectedSourceImportContext(sourceImport) && !Array.isArray(changes.pe_evaluations)) {
    return jsonResponse({ error: "Protected imports require evaluation updates.", code: "source_import_invalid", reason: "source_import_invalid", retryable: false }, 400);
  }
  if (sourceImport?.importType === "FILE_IMPORT" && (!Array.isArray(changes.pe_evaluations) || Object.keys(changes).some((key) => key !== "pe_evaluations"))) {
    return jsonResponse({ error: "Evaluation file imports require evaluation changes only.", code: "source_import_invalid", reason: "source_import_invalid", retryable: false }, 400);
  }
  if (sourceImport && isMasterDataSourceImportContext(sourceImport)) {
    const requiredKey = sourceImport.importType === "EMPLOYEE" ? "pe_employees" : "pe_criteria";
    if (!Array.isArray(changes[requiredKey])) {
      return jsonResponse({ error: "Master-data imports require their target records.", code: "source_import_invalid", reason: "source_import_invalid", retryable: false }, 400);
    }
  }
  const nonAdminSystemLogsOnly = data.session.role !== "admin" && Object.keys(changes).every((key) => key === "pe_system_logs");
  if (data.session.role !== "admin") delete changes.pe_system_logs;
  if (!operationId && !nonAdminSystemLogsOnly) {
    return jsonResponse({ error: "\u0628\u0631\u0627\u06CC \u0647\u0631 \u062A\u063A\u06CC\u06CC\u0631 \u0628\u0627\u06CC\u062F \u0634\u0646\u0627\u0633\u0647 \u06CC\u06A9\u062A\u0627\u06CC \u0639\u0645\u0644\u06CC\u0627\u062A \u0627\u0631\u0633\u0627\u0644 \u0634\u0648\u062F.", code: "operation_id_required", reason: "operation_id_required", retryable: false }, 400);
  }
  const { state: current, meta: currentMeta } = await readState(env, typeof operationId === "string" ? operationId : void 0);
  const payloadHash = operationId ? await stateOperationHash(body) : void 0;
  const receipt = operationId && env.TRANSACTION_STORE.receipt(String(operationId));
  if (receipt) {
    if (receipt.actorId !== data.session.id) return jsonResponse({ error: "\u0627\u06CC\u0646 \u0634\u0646\u0627\u0633\u0647 \u0639\u0645\u0644\u06CC\u0627\u062A \u0642\u0628\u0644\u0627\u064B \u0627\u0633\u062A\u0641\u0627\u062F\u0647 \u0634\u062F\u0647 \u0627\u0633\u062A.", code: "operation_id_reused", reason: "operation_id_reused", retryable: false }, 409);
    if (receipt.payloadHash !== payloadHash) return jsonResponse({ error: "\u0627\u06CC\u0646 \u0634\u0646\u0627\u0633\u0647 \u0639\u0645\u0644\u06CC\u0627\u062A \u0642\u0628\u0644\u0627\u064B \u0628\u0631\u0627\u06CC \u062A\u063A\u06CC\u06CC\u0631 \u062F\u06CC\u06AF\u0631\u06CC \u0627\u0633\u062A\u0641\u0627\u062F\u0647 \u0634\u062F\u0647 \u0627\u0633\u062A.", code: "operation_id_reused", reason: "operation_id_reused", retryable: false }, 409);
    return responseEnvelope(current, currentMeta, data.session, { operationId: String(operationId), payloadHash: String(receipt.payloadHash), acceptedRevision: Number(receipt.acceptedRevision) });
  }
  const baseRevision = Number(body.baseRevision);
  data.diagnostics.baseRevision = Number.isInteger(baseRevision) ? baseRevision : void 0;
  if (!Number.isInteger(baseRevision) || baseRevision !== currentMeta.revision) {
    return jsonResponse({
      error: "\u062F\u0627\u062F\u0647 \u0627\u0628\u0631\u06CC \u062F\u0631 \u0645\u0631\u0648\u0631\u06AF\u0631 \u062F\u06CC\u06AF\u0631\u06CC \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F\u0647 \u0627\u0633\u062A\u061B \u0622\u062E\u0631\u06CC\u0646 \u0646\u0633\u062E\u0647 \u062F\u0631\u06CC\u0627\u0641\u062A \u0648 \u0630\u062E\u06CC\u0631\u0647 \u062F\u0648\u0628\u0627\u0631\u0647 \u0627\u0646\u062C\u0627\u0645 \u0634\u0648\u062F.",
      code: "revision_conflict",
      reason: "stale_revision",
      retryable: false,
      revision: currentMeta.revision,
      updatedAt: currentMeta.updatedAt
    }, 409);
  }
  data.diagnostics.serverRevision = currentMeta.revision;
  if (body.employeePatch !== void 0 && typeof body.employeePatch !== "boolean") return jsonResponse({ error: "Invalid personnel mutation mode." }, 400);
  if (body.employeePatch === true) {
    if (!operationId || !Array.isArray(changes.pe_employees) || changes.pe_employees.length > 1e3 || !validateMasterDataImport(current, changes, data.session, { importType: "EMPLOYEE", operationId: String(operationId) })) return jsonResponse({ error: "\u062A\u063A\u06CC\u06CC\u0631 \u067E\u0631\u0633\u0646\u0644\u06CC \u0646\u0627\u0645\u0639\u062A\u0628\u0631 \u06CC\u0627 \u062E\u0627\u0631\u062C \u0627\u0632 \u0645\u062C\u0648\u0632 \u0627\u0633\u062A.", code: "employee_patch_denied", retryable: false }, 403);
    const byId = new Map(getEmployees(current).map((e) => [e.id, e]));
    const personnelValue = /* @__PURE__ */ __name((e) => e ? JSON.stringify(Object.fromEntries(Object.entries(e).filter(([k]) => k !== "personnelRevision" && k !== "personnelUpdatedAt").sort(([a], [b]) => a.localeCompare(b)))) : void 0, "personnelValue");
    for (const e of changes.pe_employees) {
      const previous = byId.get(e.id);
      if (personnelValue(previous) === personnelValue(e)) continue;
      byId.set(e.id, { ...e, personnelRevision: (previous?.personnelRevision || 0) + 1, personnelUpdatedAt: (/* @__PURE__ */ new Date()).toISOString() });
    }
    changes.pe_employees = [...byId.values()];
  }
  if ("pe_job_family_assignments" in changes && (data.session.role !== "admin" || !changes.pe_job_family_assignments || typeof changes.pe_job_family_assignments !== "object" || Array.isArray(changes.pe_job_family_assignments) || !Object.values(changes.pe_job_family_assignments).every((a) => a && validateApprovedFamilyAssignment(a, getProfiles(current), current.pe_criteria || [])))) return jsonResponse({ error: "\u0646\u06AF\u0627\u0634\u062A \u062E\u0627\u0646\u0648\u0627\u062F\u0647 \u0646\u06CC\u0627\u0632\u0645\u0646\u062F \u067E\u0631\u0648\u0641\u0627\u06CC\u0644 \u0645\u0639\u062A\u0628\u0631 \u0628\u0627 \u0645\u062C\u0645\u0648\u0639 \u0648\u0632\u0646 \u06F1\u06F0\u06F0 \u0648 \u0645\u0631\u062C\u0639 \u062A\u0623\u06CC\u06CC\u062F \u0627\u0633\u062A.", code: "job_family_assignment_invalid", retryable: false }, 403);
  if (data.session.role === "admin" && "pe_employees" in changes && Array.isArray(current.pe_violations) && Array.isArray(changes.pe_employees)) {
    const employeeIds = new Set(changes.pe_employees.map((e) => e.id));
    if (current.pe_violations.some((r) => !employeeIds.has(r.employeeId))) return jsonResponse({ error: "\u06A9\u0627\u0631\u0645\u0646\u062F \u062F\u0627\u0631\u0627\u06CC \u0633\u0627\u0628\u0642\u0647 \u062A\u062E\u0644\u0641 \u0642\u0627\u0628\u0644 \u062D\u0630\u0641 \u0646\u06CC\u0633\u062A\u061B \u062A\u0627\u0631\u06CC\u062E\u0686\u0647 \u0628\u0627\u06CC\u062F \u062D\u0641\u0638 \u0634\u0648\u062F.", code: "employee_has_violation_history", retryable: false }, 403);
  }
  if ("pe_violations" in changes) return jsonResponse({ error: "\u0633\u0648\u0627\u0628\u0642 \u062A\u062E\u0644\u0641 \u0641\u0642\u0637 \u0627\u0632 \u0645\u0633\u06CC\u0631 \u0627\u0642\u062F\u0627\u0645 \u0645\u0639\u062A\u0628\u0631 \u062A\u063A\u06CC\u06CC\u0631 \u0645\u06CC\u200C\u06A9\u0646\u0646\u062F.", code: "violation_direct_write_forbidden", retryable: false }, 403);
  if ("pe_violation_policy" in changes && (data.session.role !== "admin" || !validViolationPolicy(changes.pe_violation_policy))) return jsonResponse({ error: "\u0633\u06CC\u0627\u0633\u062A \u062A\u062E\u0644\u0641\u0627\u062A \u0645\u0639\u062A\u0628\u0631 \u0648 \u0645\u062C\u0648\u0632 \u0645\u062F\u06CC\u0631 \u0644\u0627\u0632\u0645 \u0627\u0633\u062A.", code: "violation_policy_invalid", retryable: false }, 403);
  const violationCommands = changes.pe_violation_operations;
  delete changes.pe_violation_operations;
  if (Array.isArray(changes.pe_evaluations)) {
    const byId = new Map((current.pe_evaluations || []).map((e) => [e.id, e]));
    if (changes.pe_evaluations.some((e) => (e.approvedDeduction ?? 0) !== (byId.get(e.id)?.approvedDeduction ?? 0))) return jsonResponse({ error: "\u06A9\u0633\u0631 \u0627\u0645\u062A\u06CC\u0627\u0632 \u0641\u0642\u0637 \u0631\u0648\u06CC \u0633\u0631\u0648\u0631 \u0645\u062D\u0627\u0633\u0628\u0647 \u0645\u06CC\u200C\u0634\u0648\u062F.", code: "deduction_direct_write_forbidden", retryable: false }, 403);
  }
  if (nonAdminSystemLogsOnly) return responseEnvelope(current, currentMeta, data.session, void 0, String(operationId));
  if (body.evaluationPatch === true) {
    if (!operationId || !Array.isArray(changes.pe_evaluations)) return jsonResponse({ error: "Changed-set operations require evaluation records." }, 400);
    const updates = changes.pe_evaluations;
    const updateMap = new Map(updates.map((record) => [record?.id, record]));
    if (updateMap.size !== updates.length || updates.some((record) => !record?.id)) return jsonResponse({ error: "Duplicate or missing evaluation ID." }, 400);
    const records = Array.isArray(current.pe_evaluations) ? current.pe_evaluations : [];
    const deleteIds = body.evaluationDeleteIds === void 0 ? [] : body.evaluationDeleteIds;
    if (!Array.isArray(deleteIds) || deleteIds.some((id) => typeof id !== "string") || new Set(deleteIds).size !== deleteIds.length || deleteIds.some((id) => updateMap.has(id))) {
      return jsonResponse({ error: "\u0634\u0646\u0627\u0633\u0647\u200C\u0647\u0627\u06CC \u062D\u0630\u0641 \u0627\u0631\u0632\u06CC\u0627\u0628\u06CC \u0645\u0639\u062A\u0628\u0631 \u0646\u06CC\u0633\u062A\u0646\u062F.", code: "evaluation_delete_invalid", reason: "invalid_changed_set", retryable: false }, 400);
    }
    const expected = body.evaluationExpected;
    const changedIds = /* @__PURE__ */ new Set([...updateMap.keys(), ...deleteIds]);
    if (expected !== void 0 && (!expected || typeof expected !== "object" || Array.isArray(expected) || Object.keys(expected).length !== changedIds.size || Object.keys(expected).some((id) => !changedIds.has(id) || expected[id] !== null && (typeof expected[id] !== "string" || !/^[a-f0-9]{64}$/i.test(expected[id]))))) {
      return jsonResponse({ error: "\u0646\u0633\u062E\u0647 \u0645\u0628\u0646\u0627\u06CC \u0631\u06A9\u0648\u0631\u062F\u0647\u0627\u06CC \u062A\u063A\u06CC\u06CC\u0631 \u06CC\u0627\u0641\u062A\u0647 \u0645\u0639\u062A\u0628\u0631 \u0646\u06CC\u0633\u062A.", code: "evaluation_baseline_invalid", reason: "invalid_changed_set", retryable: false }, 400);
    }
    const currentById = new Map(records.map((record) => [record.id, record]));
    for (const id of expected ? changedIds : []) {
      const stored = currentById.get(id);
      const digest2 = stored ? Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(stored))))).map((byte) => byte.toString(16).padStart(2, "0")).join("") : null;
      if (digest2 !== expected[id]) {
        return jsonResponse({ error: "\u06CC\u06A9\u06CC \u0627\u0632 \u067E\u0631\u0648\u0646\u062F\u0647\u200C\u0647\u0627\u06CC \u0627\u0646\u062A\u062E\u0627\u0628\u200C\u0634\u062F\u0647 \u0631\u0648\u06CC \u0633\u0631\u0648\u0631 \u062A\u063A\u06CC\u06CC\u0631 \u06A9\u0631\u062F\u0647 \u0627\u0633\u062A\u061B \u0646\u0633\u062E\u0647 \u062A\u0627\u0632\u0647 \u0631\u0627 \u0628\u0627\u0631\u06AF\u0630\u0627\u0631\u06CC \u0648 \u062F\u0648\u0628\u0627\u0631\u0647 \u0628\u0631\u0631\u0633\u06CC \u06A9\u0646\u06CC\u062F.", code: "evaluation_revision_conflict", reason: "evaluation_changed_on_server", retryable: false, revision: currentMeta.revision }, 409);
      }
    }
    if (deleteIds.length && data.session.role !== "admin") return jsonResponse({ error: "\u062D\u0630\u0641 \u067E\u0631\u0648\u0646\u062F\u0647 \u0641\u0642\u0637 \u0628\u0631\u0627\u06CC \u0645\u062F\u06CC\u0631 \u0633\u06CC\u0633\u062A\u0645 \u0645\u062C\u0627\u0632 \u0627\u0633\u062A.", code: "permission_denied", reason: "permission_denied", retryable: false }, 403);
    if (deleteIds.some((id) => {
      const evaluation = currentById.get(id);
      return evaluation && (current.pe_violations || []).some((record) => record.employeeId === evaluation.empId && record.periodId === getEvaluationPeriodId(evaluation));
    })) return jsonResponse({ error: "\u067E\u0631\u0648\u0646\u062F\u0647 \u062F\u0627\u0631\u0627\u06CC \u062A\u0627\u0631\u06CC\u062E\u0686\u0647 \u062A\u062E\u0644\u0641 \u0642\u0627\u0628\u0644 \u062D\u0630\u0641 \u0646\u06CC\u0633\u062A.", code: "evaluation_has_violation_history", retryable: false }, 403);
    if (deleteIds.some((id) => {
      const record = currentById.get(id);
      return !record || record.status === "locked" || record.stage === "completed";
    })) {
      return jsonResponse({ error: "\u067E\u0631\u0648\u0646\u062F\u0647 \u0646\u0647\u0627\u06CC\u06CC \u06CC\u0627 \u0642\u0641\u0644\u200C\u0634\u062F\u0647 \u0642\u0627\u0628\u0644 \u062D\u0630\u0641 \u0646\u06CC\u0633\u062A.", code: "finalized_record_locked", reason: "finalized_record_locked", retryable: false }, 403);
    }
    const oldIds = new Set(records.map((record) => record.id));
    const deleted = new Set(deleteIds);
    changes.pe_evaluations = [...records.filter((record) => !deleted.has(record.id)).map((record) => updateMap.get(record.id) || record), ...updates.filter((record) => !oldIds.has(record.id))];
  }
  const canonicalChanges = resolveTransitionOwners(current, changes, data.session);
  if ("pe_workflow_sla" in canonicalChanges) {
    if (data.session.role !== "admin") return jsonResponse({ error: "\u062A\u0646\u0638\u06CC\u0645 \u0645\u0647\u0644\u062A\u200C\u0647\u0627\u06CC \u06AF\u0631\u062F\u0634 \u06A9\u0627\u0631 \u0641\u0642\u0637 \u0628\u0631\u0627\u06CC \u0645\u062F\u06CC\u0631 \u0633\u06CC\u0633\u062A\u0645 \u0645\u062C\u0627\u0632 \u0627\u0633\u062A.", code: "permission_denied", reason: "permission_denied", retryable: false }, 403);
    if (!isValidWorkflowSlaConfig(canonicalChanges.pe_workflow_sla)) return jsonResponse({ error: "\u067E\u06CC\u06A9\u0631\u0628\u0646\u062F\u06CC \u0645\u0647\u0644\u062A \u06AF\u0631\u062F\u0634 \u06A9\u0627\u0631 \u0645\u0639\u062A\u0628\u0631 \u0646\u06CC\u0633\u062A.", code: "workflow_sla_invalid", reason: "invalid_configuration", retryable: false }, 400);
  }
  if (!hasAuthorizedEvaluationChanges(current, canonicalChanges, data.session, sourceImport)) {
    return safeWriteDenialResponse(current, canonicalChanges, data.session, sourceImport);
  }
  if (Array.isArray(canonicalChanges.pe_evaluations)) {
    const existing = new Map((Array.isArray(current.pe_evaluations) ? current.pe_evaluations : []).map((item) => [item.id, item]));
    const ids = /* @__PURE__ */ new Set();
    const periodEmployees = new Set((Array.isArray(current.pe_evaluations) ? current.pe_evaluations : []).map((item) => `${item.empId}\0${getEvaluationPeriodId(item)}`));
    for (const item of canonicalChanges.pe_evaluations) {
      const old = existing.get(item.id);
      if (!old && (ids.has(item.id) || periodEmployees.has(`${item.empId}\0${getEvaluationPeriodId(item)}`))) return jsonResponse({ error: "An evaluation already exists for this employee and period." }, 409);
      ids.add(item.id);
      periodEmployees.add(`${item.empId}\0${getEvaluationPeriodId(item)}`);
    }
  }
  const acceptedAt = (/* @__PURE__ */ new Date()).toISOString();
  const next = mergeAuthorizedState(current, canonicalChanges, data.session, sourceImport);
  if (violationCommands !== void 0) {
    const actor = getActor(current, data.session);
    if (!actor) return jsonResponse({ error: "\u06A9\u0627\u0631\u0628\u0631 \u0645\u062C\u0627\u0632 \u0646\u06CC\u0633\u062A." }, 403);
    try {
      const result = applyViolationCommands({ records: current.pe_violations || [], evaluations: next.pe_evaluations || [], employees: getEmployees(current), actor, permissions: getPermissionPolicy(current), policy: current.pe_violation_policy || EMPTY_VIOLATION_POLICY, commands: violationCommands, operationId: String(operationId), now: acceptedAt });
      next.pe_violations = result.records;
      next.pe_evaluations = result.evaluations;
      next.pe_audit_logs = [...result.audit, ...next.pe_audit_logs || []];
    } catch (error) {
      if (error instanceof ViolationError) return jsonResponse({ error: error.message, code: "violation_action_rejected", retryable: false }, error.status);
      throw error;
    }
  }
  if ("pe_violation_policy" in canonicalChanges) next.pe_audit_logs = [{ id: `audit:violation_policy:${operationId}`, timestamp: acceptedAt, actorId: data.session.id, action: "violation_policy_updated", previousState: current.pe_violation_policy || null, resultingState: canonicalChanges.pe_violation_policy, result: "accepted" }, ...next.pe_audit_logs || []];
  if ("pe_job_family_assignments" in canonicalChanges) next.pe_audit_logs = [{ id: `audit:job_family:${operationId}`, timestamp: acceptedAt, actorId: data.session.id, action: "job_family_assignment_approved", previousState: current.pe_job_family_assignments || null, resultingState: canonicalChanges.pe_job_family_assignments, result: "accepted" }, ...next.pe_audit_logs || []];
  const evaluationConfigurationChanged = data.session.role === "admin" && ["pe_criteria", "pe_profiles"].some(
    (key) => key in canonicalChanges && JSON.stringify(canonicalChanges[key]) !== JSON.stringify(current[key])
  );
  if (evaluationConfigurationChanged) {
    const previousEvaluations = Array.isArray(next.pe_evaluations) ? next.pe_evaluations : [];
    const reconciledEvaluations = reconcileActiveEvaluations(
      previousEvaluations,
      Array.isArray(next.pe_profiles) ? next.pe_profiles : [],
      Array.isArray(next.pe_criteria) ? next.pe_criteria : []
    );
    const previousById = new Map(previousEvaluations.map((item) => [item.id, item]));
    const previousProfiles = Array.isArray(current.pe_profiles) ? current.pe_profiles : [];
    const previousCriteria = Array.isArray(current.pe_criteria) ? current.pe_criteria : [];
    const resultingProfiles = Array.isArray(next.pe_profiles) ? next.pe_profiles : [];
    const resultingCriteria = Array.isArray(next.pe_criteria) ? next.pe_criteria : [];
    next.pe_evaluations = reconciledEvaluations;
    const audit = Array.isArray(next.pe_audit_logs) ? [...next.pe_audit_logs] : [];
    for (const item of reconciledEvaluations) {
      const previous = previousById.get(item.id);
      if (!previous) continue;
      const previousConfiguration = getEvaluationCriteriaConfigurationSnapshot(previous, previousProfiles, previousCriteria);
      const resultingConfiguration = getEvaluationCriteriaConfigurationSnapshot(item, resultingProfiles, resultingCriteria);
      const scoreSlotsChanged = JSON.stringify(item.scores) !== JSON.stringify(previous.scores) || JSON.stringify(item.retiredScores || []) !== JSON.stringify(previous.retiredScores || []);
      const configurationChanged = JSON.stringify(previousConfiguration) !== JSON.stringify(resultingConfiguration);
      if (!scoreSlotsChanged && !configurationChanged) continue;
      audit.unshift({
        id: `audit:criteria_reconcile:${crypto.randomUUID()}`,
        timestamp: acceptedAt,
        actorId: data.session.id,
        actorName: data.session.name,
        actorRole: data.session.role,
        action: scoreSlotsChanged ? "evaluation_criteria_reconciled" : "evaluation_criteria_configuration_updated",
        target: item.id,
        evaluationId: item.id,
        employeeId: item.empId,
        profileId: item.profileId,
        previousState: {
          scores: previous.scores,
          retiredScores: previous.retiredScores || [],
          criteriaConfiguration: previousConfiguration
        },
        resultingState: {
          scores: item.scores,
          retiredScores: item.retiredScores || [],
          criteriaConfiguration: resultingConfiguration
        },
        result: "accepted"
      });
    }
    if (audit.length !== (Array.isArray(next.pe_audit_logs) ? next.pe_audit_logs.length : 0)) {
      next.pe_audit_logs = audit;
    }
  }
  const acceptedReceipt = { operationId: String(operationId), actorId: data.session.id, actorUsername: data.session.username, payloadHash, acceptedRevision: currentMeta.revision + 1, timestamp: acceptedAt, clientId: typeof body.clientId === "string" ? body.clientId.slice(0, 80) : void 0 };
  const meta = {
    revision: currentMeta.revision + 1,
    updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
    updatedBy: data.session.username,
    clientId: typeof body.clientId === "string" ? body.clientId.slice(0, 80) : void 0
  };
  try {
    const ack = env.TRANSACTION_STORE.commit(current, next, currentMeta.revision, meta, acceptedReceipt);
    const visible = scopedState(next, data.session);
    const patch = {};
    for (const [key, value] of Object.entries(ack.state)) {
      if (!(key in visible)) continue;
      if (Array.isArray(value) && !ack.replacementKeys.includes(key)) {
        if (data.session.role === "admin" && key !== "pe_notifications") patch[key] = value;
        else {
          const allowed = new Set((visible[key] || []).map((row) => row.id));
          patch[key] = value.filter((row) => allowed.has(row.id));
        }
      } else patch[key] = visible[key];
    }
    return jsonResponse({ state: patch, statePatch: true, deletedStateIds: ack.deletedStateIds, replacementKeys: ack.replacementKeys, ...meta, accepted: true, operationId, payloadHash, acceptedRevision: meta.revision, storage: "sqlite-durable-object", protocolVersion: 2, storageMetrics: ack.metrics });
  } catch {
    throw new StateStoreUnavailable("transaction_commit_failed", String(operationId), "kv_state_write", false, Date.now() - data.diagnostics.startedAt);
  }
}
__name(writeState, "writeState");

// ../cloudflare/stateBackup.ts
function snapshotCounts(state) {
  return Object.fromEntries(Object.entries(state).filter(([, v]) => Array.isArray(v)).map(([k, v]) => [k, v.length]));
}
__name(snapshotCounts, "snapshotCounts");
function validateSnapshot(state, meta) {
  if (!state || typeof state !== "object" || Array.isArray(state) || Object.keys(sanitizeCloudState(state, true)).length !== Object.keys(state).length) throw Error("Unknown or malformed snapshot keys");
  if (!Number.isSafeInteger(meta?.revision) || meta.revision < 0 || typeof meta.updatedAt !== "string") throw Error("Invalid snapshot revision");
  const unique = /* @__PURE__ */ __name((key) => {
    const rows = state[key] || [];
    if (!Array.isArray(rows)) throw Error("Invalid collection " + key);
    const ids = /* @__PURE__ */ new Set();
    for (const row of rows) {
      if (!row || typeof row.id !== "string" || !row.id || ids.has(row.id)) throw Error("Duplicate/missing ID in " + key);
      ids.add(row.id);
    }
    return ids;
  }, "unique");
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
__name(validateSnapshot, "validateSnapshot");
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => [k, canonical(v)]));
  return value;
}
__name(canonical, "canonical");
async function digest(value) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(canonical(value)))))).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(digest, "digest");
async function sealSnapshot(state, meta) {
  validateSnapshot(state, meta);
  const normalized = { ...state, __operation_receipts: [...state.__operation_receipts || []].sort((a, b) => a.operationId < b.operationId ? -1 : a.operationId > b.operationId ? 1 : 0) };
  const data = { format: "chalak-state-backup-v1", state: normalized, meta, counts: snapshotCounts(normalized) };
  return { ...data, sha256: await digest(data) };
}
__name(sealSnapshot, "sealSnapshot");
async function verifySnapshot(backup) {
  if (backup?.format !== "chalak-state-backup-v1") throw Error("Unsupported backup");
  validateSnapshot(backup.state, backup.meta);
  const raw = { format: backup.format, state: backup.state, meta: backup.meta, counts: snapshotCounts(backup.state) };
  if (await digest(raw) !== backup.sha256 || JSON.stringify(canonical(raw.counts)) !== JSON.stringify(canonical(backup.counts))) throw Error("Backup checksum/count mismatch");
  const receipts = backup.state.__operation_receipts;
  if (receipts && receipts.every((r, i) => i === 0 || receipts[i - 1].operationId < r.operationId)) return backup;
  return sealSnapshot(backup.state, backup.meta);
}
__name(verifySnapshot, "verifySnapshot");

// index.ts
var chunks = /* @__PURE__ */ __name((text2) => {
  const result = [];
  for (let i = 0; i < text2.length; ) {
    let end = Math.min(i + 64e3, text2.length);
    if (end < text2.length && text2.charCodeAt(end - 1) >= 55296 && text2.charCodeAt(end - 1) <= 56319) end--;
    result.push(text2.slice(i, end));
    i = end;
  }
  return result.length ? result : [""];
}, "chunks");
function patchable(value) {
  return Array.isArray(value) && value.every((row) => row && typeof row === "object" && typeof row.id === "string") && new Set(value.map((r) => r.id)).size === value.length;
}
__name(patchable, "patchable");
var ChalakState = class extends DurableObject {
  static {
    __name(this, "ChalakState");
  }
  constructor(ctx, env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS control(id INTEGER PRIMARY KEY CHECK(id=1),initialized INTEGER NOT NULL,mode TEXT NOT NULL,meta TEXT NOT NULL,migration_hash TEXT);INSERT OR IGNORE INTO control VALUES(1,0,'frozen','{"revision":0,"updatedAt":""}',NULL);CREATE TABLE IF NOT EXISTS collections(key TEXT PRIMARY KEY,kind TEXT NOT NULL);CREATE TABLE IF NOT EXISTS state_rows(collection TEXT NOT NULL,identity TEXT NOT NULL,ordinal INTEGER NOT NULL,part INTEGER NOT NULL,value TEXT NOT NULL,PRIMARY KEY(collection,identity,part));CREATE INDEX IF NOT EXISTS state_order ON state_rows(collection,ordinal,part);CREATE TABLE IF NOT EXISTS receipts(operation_id TEXT PRIMARY KEY,value TEXT NOT NULL);`);
  }
  control() {
    return this.ctx.storage.sql.exec("SELECT initialized,mode,meta,migration_hash FROM control WHERE id=1").one();
  }
  load() {
    if (this.cache) return this.cache;
    const state = {};
    for (const { key, kind } of this.ctx.storage.sql.exec("SELECT key,kind FROM collections").toArray()) {
      const rows = this.ctx.storage.sql.exec("SELECT identity,value FROM state_rows WHERE collection=? ORDER BY ordinal,part", key).toArray();
      const encoded = /* @__PURE__ */ new Map();
      for (const row of rows) encoded.set(row.identity, (encoded.get(row.identity) || "") + row.value);
      state[key] = kind === "array" || kind === "audit" ? [...encoded.values()].map((value) => JSON.parse(value)) : JSON.parse([...encoded.values()].join(""));
    }
    this.cache = state;
    return state;
  }
  read() {
    const c = this.control();
    if (!c.initialized) throw Error("Migration required");
    return { state: this.load(), meta: JSON.parse(c.meta) };
  }
  receipt(id) {
    const rows = this.ctx.storage.sql.exec("SELECT value FROM receipts WHERE operation_id=?", id).toArray();
    return rows.length ? JSON.parse(rows[0].value) : void 0;
  }
  writeRecord(key, id, ordinal, value, metrics) {
    const text2 = JSON.stringify(value);
    metrics.serializedRecords++;
    if (key === "pe_audit_logs") metrics.auditRecords++;
    if (key === "pe_evaluations") metrics.evaluationRecords++;
    this.ctx.storage.sql.exec("DELETE FROM state_rows WHERE collection=? AND identity=?", key, id);
    metrics.sqlWrites++;
    chunks(text2).forEach((chunk, part) => {
      this.ctx.storage.sql.exec("INSERT INTO state_rows(collection,identity,ordinal,part,value) VALUES(?,?,?,?,?)", key, id, ordinal, part, chunk);
      metrics.sqlWrites++;
    });
  }
  persist(current, next) {
    const ack = { state: {}, replacementKeys: [], deletedStateIds: {}, metrics: { serializedRecords: 0, auditRecords: 0, evaluationRecords: 0, sqlWrites: 0 } };
    for (const [key, value] of Object.entries(next)) {
      if (key === "__operation_receipts" || value === current[key]) continue;
      const old = current[key];
      if (key === "pe_audit_logs") {
        if (!Array.isArray(value) || old !== void 0 && !Array.isArray(old)) throw Error("Invalid audit");
        const previous = old || [];
        const first = previous[0];
        const prefix = first === void 0 ? value.length : value.indexOf(first);
        if (prefix < 0 || value.length !== prefix + previous.length || previous.length > 0 && value[value.length - 1] !== previous[previous.length - 1]) throw Error("Audit history is append-only");
        this.ctx.storage.sql.exec("INSERT OR REPLACE INTO collections(key,kind) VALUES(?,?)", key, "audit");
        const min = this.ctx.storage.sql.exec("SELECT MIN(ordinal) AS n FROM state_rows WHERE collection=?", key).one().n ?? 0;
        value.slice(0, prefix).forEach((row, i) => this.writeRecord(key, crypto.randomUUID(), min - prefix + i, row, ack.metrics));
        continue;
      }
      if (patchable(value) && (!old || patchable(old))) {
        const before = old || [];
        const beforeMap = new Map(before.map((v, i) => [v.id, { v, i }]));
        const afterIds = new Set(value.map((v) => v.id));
        ack.state[key] = [];
        this.ctx.storage.sql.exec("INSERT OR REPLACE INTO collections(key,kind) VALUES(?,?)", key, "array");
        for (const row of before) if (!afterIds.has(row.id)) {
          this.ctx.storage.sql.exec("DELETE FROM state_rows WHERE collection=? AND identity=?", key, row.id);
          (ack.deletedStateIds[key] ||= []).push(row.id);
          ack.metrics.sqlWrites++;
        }
        value.forEach((row, i) => {
          const previous = beforeMap.get(row.id);
          if (row !== previous?.v) {
            this.writeRecord(key, row.id, i, row, ack.metrics);
            ack.state[key].push(row);
          } else if (previous.i !== i) {
            this.ctx.storage.sql.exec("UPDATE state_rows SET ordinal=? WHERE collection=? AND identity=?", i, key, row.id);
            ack.metrics.sqlWrites++;
          }
        });
      } else {
        this.ctx.storage.sql.exec("DELETE FROM state_rows WHERE collection=?", key);
        this.ctx.storage.sql.exec("INSERT OR REPLACE INTO collections(key,kind) VALUES(?,?)", key, "json");
        this.writeRecord(key, "json", 0, value, ack.metrics);
        ack.state[key] = value;
        ack.replacementKeys.push(key);
      }
    }
    return ack;
  }
  commit(current, next, expectedRevision, meta, receipt) {
    let result;
    this.ctx.storage.transactionSync(() => {
      const c = this.control();
      if (c.mode !== "active" || !c.initialized || JSON.parse(c.meta).revision !== expectedRevision || meta.revision !== expectedRevision + 1 || receipt.acceptedRevision !== meta.revision || this.receipt(receipt.operationId)) throw Error("Atomic precondition failed");
      result = this.persist(current, next);
      this.ctx.storage.sql.exec("INSERT INTO receipts(operation_id,value) VALUES(?,?)", receipt.operationId, JSON.stringify(receipt));
      this.ctx.storage.sql.exec("UPDATE control SET meta=? WHERE id=1", JSON.stringify(meta));
    });
    this.cache = next;
    return result;
  }
  async maintenance(request) {
    const supplied = request.headers.get("Authorization") || "";
    const secret = this.env.STORAGE_MAINTENANCE_TOKEN;
    if (!secret || secret.length < 32 || supplied !== "Bearer " + secret) return jsonResponse({ error: "Operator authorization required" }, 403);
    if (request.method !== "POST") return jsonResponse({ error: "POST required" }, 405);
    const raw = await request.text();
    if (new TextEncoder().encode(raw).byteLength > 3e7) return jsonResponse({ error: "Backup too large" }, 413);
    const body = JSON.parse(raw);
    const c = this.control();
    if (body.action === "status") return jsonResponse({ initialized: !!c.initialized, mode: c.mode, meta: JSON.parse(c.meta), migrationHash: c.migration_hash });
    if (body.action === "dry-run" || body.action === "migrate") {
      let backup;
      try {
        backup = await verifySnapshot(body.backup);
      } catch {
        return jsonResponse({ error: "Backup validation failed", code: "backup_invalid" }, 400);
      }
      if (body.action === "dry-run") return jsonResponse({ valid: true, counts: backup.counts, revision: backup.meta.revision, sha256: backup.sha256, receiptShapeNormalized: backup.sha256 !== body.backup.sha256 });
      if (c.initialized) return c.migration_hash === backup.sha256 || c.migration_hash === body.backup.sha256 ? jsonResponse({ migrated: true, replayed: true, revision: JSON.parse(c.meta).revision, sha256: backup.sha256 }) : jsonResponse({ error: "Authority already initialized" }, 409);
      this.ctx.storage.transactionSync(() => {
        if (this.control().initialized) throw Error("Migration race");
        const { __operation_receipts: receipts, ...state } = backup.state;
        this.persist({}, state);
        for (const receipt of receipts || []) this.ctx.storage.sql.exec("INSERT INTO receipts(operation_id,value) VALUES(?,?)", receipt.operationId, JSON.stringify(receipt));
        this.ctx.storage.sql.exec("UPDATE control SET initialized=1,mode='frozen',meta=?,migration_hash=? WHERE id=1", JSON.stringify(backup.meta), backup.sha256);
      });
      this.cache = void 0;
      return jsonResponse({ migrated: true, revision: backup.meta.revision, sha256: backup.sha256, counts: backup.counts });
    }
    if (!c.initialized) return jsonResponse({ error: "Migration required" }, 503);
    const meta = JSON.parse(c.meta);
    if (body.expectedRevision !== meta.revision) return jsonResponse({ error: "Maintenance revision conflict", revision: meta.revision }, 409);
    if (body.action === "freeze" || body.action === "activate") {
      this.ctx.storage.transactionSync(() => {
        if (JSON.parse(this.control().meta).revision !== body.expectedRevision) throw Error("Revision conflict");
        this.ctx.storage.sql.exec("UPDATE control SET mode=? WHERE id=1", body.action === "freeze" ? "frozen" : "active");
      });
      return jsonResponse({ mode: body.action === "freeze" ? "frozen" : "active", revision: meta.revision });
    }
    if (body.action === "export") {
      if (c.mode !== "frozen") return jsonResponse({ error: "Freeze all authoritative writes before export" }, 409);
      const receipts = this.ctx.storage.sql.exec("SELECT value FROM receipts ORDER BY operation_id").toArray().map((r) => JSON.parse(r.value));
      return jsonResponse(await sealSnapshot({ ...this.load(), __operation_receipts: receipts }, meta));
    }
    return jsonResponse({ error: "Unknown maintenance action" }, 400);
  }
  fetch(request) {
    return this.ctx.blockConcurrencyWhile(async () => {
      try {
        const path = new URL(request.url).pathname;
        if (path === "/api/storage") return await this.maintenance(request);
        const c = this.control();
        if (path === "/internal/health") return jsonResponse({ status: c.initialized && c.mode === "active" ? "ok" : "maintenance", storage: "sqlite-durable-object", version: "7.0.0", revision: JSON.parse(c.meta).revision, initialized: !!c.initialized, mode: c.mode }, c.initialized && c.mode === "active" ? 200 : 503);
        if (!c.initialized) return jsonResponse({ error: "\u0645\u0631\u062C\u0639 \u062A\u0631\u0627\u06A9\u0646\u0634\u06CC \u0647\u0646\u0648\u0632 \u0645\u0647\u0627\u062C\u0631\u062A \u0648 \u062A\u0623\u06CC\u06CC\u062F \u0646\u0634\u062F\u0647 \u0627\u0633\u062A.", code: "migration_required", retryable: false }, 503);
        if (path === "/internal/identity") {
          const state = this.load();
          return jsonResponse({ pe_employees: state.pe_employees || [], pe_locked_users: state.pe_locked_users || [] });
        }
        if (path !== "/api/state" && path !== "/internal/import-history") return jsonResponse({ error: "Not found" }, 404);
        const env = { ...this.env, TRANSACTION_STORE: this };
        const session = await readSession(request, env);
        if (!session) return jsonResponse({ error: "Authentication required", code: "authentication_required", retryable: false }, 401);
        if (request.method === "POST" && c.mode !== "active") return jsonResponse({ error: "\u0630\u062E\u06CC\u0631\u0647 \u0628\u0631\u0627\u06CC \u0645\u0647\u0627\u062C\u0631\u062A \u06CC\u0627 \u0628\u0627\u0632\u06AF\u0634\u062A \u0645\u0648\u0642\u062A\u0627\u064B \u0645\u062A\u0648\u0642\u0641 \u0627\u0633\u062A\u061B \u062A\u063A\u06CC\u06CC\u0631\u0627\u062A \u062D\u0641\u0638 \u0634\u062F\u0646\u062F.", code: "authority_frozen", retryable: false }, 503);
        const context = { request, env, data: { session } };
        if (path === "/internal/import-history") return onRequestGet(context);
        const response = request.method === "GET" ? await onRequestGet2(context) : request.method === "POST" ? await onRequestPost(context) : jsonResponse({ error: "Method not allowed" }, 405);
        if (request.method === "POST" && response.ok) await this.ctx.storage.sync();
        return response;
      } catch (error) {
        console.error(JSON.stringify({ event: "authority_request_failed", type: error instanceof Error ? error.name : "unknown" }));
        return jsonResponse({ error: "\u062F\u0631\u062E\u0648\u0627\u0633\u062A \u0645\u0631\u062C\u0639 \u062A\u0631\u0627\u06A9\u0646\u0634\u06CC \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062F\u061B \u0630\u062E\u06CC\u0631\u0647 \u062A\u0623\u06CC\u06CC\u062F \u0646\u0634\u062F\u0647 \u0627\u0633\u062A.", code: "transaction_request_failed", retryable: false }, 503);
      }
    });
  }
};
var index_default = { fetch() {
  return new Response("Not found", { status: 404 });
} };
export {
  ChalakState,
  index_default as default
};
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * Workflow Authorization — Authority check for workflow actions.
 *
 * @license SPDX-License-Identifier: Apache-2.0
 */
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Formula Engine & KPI Auto-Calculation Module
 * Handles safe mathematical expression evaluation, variable substitutions,
 * threshold mapping to 1-5 scale, and validation.
 */
//# sourceMappingURL=index.js.map
