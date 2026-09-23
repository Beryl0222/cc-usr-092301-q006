// 群众赛事医疗调度 —— 合同校验与安全序列化。
//
// 安全约定：
//   * 只接受“普通 JSON 对象”自身拥有的字段，绝不沿原型链查找（不再使用 `in`）；
//   * 校验过程不调用任何可能来自合作方的代码：属性一律通过
//     getOwnPropertyNames / getOwnPropertyDescriptor 反射读取，永不求值 getter；
//   * 对空值、数组、危险键、访问器属性、循环结构、非 JSON 值给出确定的问题代码，
//     而不是抛出异常或把污染字段当作真实数据；
//   * 规范化摘要与序列化只覆盖对象自身的可枚举数据属性，原型上的任何值
//     （含敏感值）都不会进入摘要、日志或错误响应。

import { createHash } from "node:crypto";

export const EVENT_KINDS = Object.freeze([
  "EVENT_RISK_FILED",
  "RESOURCE_DECLARED",
  "PLAN_APPROVED",
  "INCIDENT_ESCALATED",
  "HANDOFF_COMPLETED",
]);

export const REQUIRED_FIELDS = Object.freeze([
  "event_id",
  "kind",
  "occurred_at",
  "subject_id",
  "payload",
]);

// 校验问题代码（稳定的机器可读契约）。
export const Problem = Object.freeze({
  EMPTY_RECORD: "EMPTY_RECORD",
  NOT_AN_OBJECT: "NOT_AN_OBJECT",
  ARRAY_REJECTED: "ARRAY_REJECTED",
  PROTOTYPE_POLLUTED: "PROTOTYPE_POLLUTED",
  DANGEROUS_KEY: "DANGEROUS_KEY",
  ACCESSOR_PROPERTY: "ACCESSOR_PROPERTY",
  CIRCULAR_STRUCTURE: "CIRCULAR_STRUCTURE",
  NON_JSON_VALUE: "NON_JSON_VALUE",
  MISSING_FIELD: "MISSING_FIELD",
  UNKNOWN_KIND: "UNKNOWN_KIND",
  UNREADABLE_RECORD: "UNREADABLE_RECORD",
});

// 自身拥有这些键即视为攻击尝试：合法 JSON 事件不会出现这些名字。
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// 防御性上限：超出即按非 JSON 数据拒绝，避免恶意输入放大遍历成本。
const MAX_DEPTH = 256;
const MAX_ARRAY_LENGTH = 4096;

function tryCall(fn) {
  try {
    return { ok: true, value: fn() };
  } catch {
    return { ok: false, value: undefined };
  }
}

function getPrototypeOfSafe(value) {
  return tryCall(() => Object.getPrototypeOf(value));
}

// Array.isArray 在已撤销的 Proxy 上会按规范抛 TypeError，统一兜底：null 表示不可读。
function isArraySafe(value) {
  const r = tryCall(() => Array.isArray(value));
  return r.ok ? r.value : null;
}

function ownKeysSafe(value) {
  // getOwnPropertyNames 只返回键名，不会触发任何 getter；Proxy 的 ownKeys
  // 陷阱若抛错，这里返回 null 交由上层记为 UNREADABLE_RECORD。
  const r = tryCall(() => Object.getOwnPropertyNames(value));
  return r.ok ? r.value : null;
}

function getOwnPropertyDescriptorSafe(value, key) {
  const r = tryCall(() => Object.getOwnPropertyDescriptor(value, key));
  return r.ok ? r.value : null;
}

function isDataDescriptor(desc) {
  return !!desc && "value" in desc && typeof desc.get !== "function" && typeof desc.set !== "function";
}

function isPlainJsonObject(value) {
  if (value === null || typeof value !== "object") return false;
  if (isArraySafe(value) !== false) return false; // 数组或不可读代理都不是普通对象
  const proto = getPrototypeOfSafe(value);
  if (!proto.ok) return false; // 连原型都读不出（恶意 Proxy），不按普通对象处理。
  // JSON.parse 结果 / 对象字面量的原型是 Object.prototype；Object.create(null) 同样可信。
  return proto.value === Object.prototype || proto.value === null;
}

function isArrayIndexKey(key) {
  return /^(0|[1-9][0-9]*)$/.test(key);
}

// 通过描述符读取数组长度：不触发 get 陷阱，且检查与遍历使用同一个值。
function arrayLengthSafe(value) {
  const desc = getOwnPropertyDescriptorSafe(value, "length");
  if (!desc || !isDataDescriptor(desc) || typeof desc.value !== "number") return 0;
  return desc.value;
}

/**
 * 仅在已确认安全的自身数据属性上读取字段值（不触发任何外来代码）。
 * 校验通过后，接收流程用它提取 event_id 等字段。
 */
export function readOwnDataValue(record, name) {
  const desc = getOwnPropertyDescriptorSafe(record, name);
  if (!desc || !desc.enumerable || !isDataDescriptor(desc)) return undefined;
  return desc.value;
}

// 深度检查 JSON 值：只认可普通对象、数组、字符串、有限数字、布尔、null。
// 全程只读属性描述符，不做属性访问，因此不会执行外来 getter / Proxy 的 get 陷阱。
function validateJsonValue(value, path, ancestors, depth, problems) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;

  if (typeof value === "number") {
    if (!Number.isFinite(value)) problems.push({ code: Problem.NON_JSON_VALUE, field: path });
    return;
  }

  if (typeof value !== "object") {
    // undefined / function / symbol / bigint 都不是 JSON 可表达值。
    problems.push({ code: Problem.NON_JSON_VALUE, field: path });
    return;
  }

  if (depth > MAX_DEPTH) {
    problems.push({ code: Problem.NON_JSON_VALUE, field: path });
    return;
  }

  if (ancestors.has(value)) {
    problems.push({ code: Problem.CIRCULAR_STRUCTURE, field: path });
    return;
  }
  ancestors.add(value);

  const isArray = isArraySafe(value);
  if (isArray === null) {
    problems.push({ code: Problem.UNREADABLE_RECORD, field: path });
    ancestors.delete(value);
    return;
  }
  if (!isArray && !isPlainJsonObject(value)) {
    // 类实例 / 被替换原型的对象 / 外来宿主对象 —— 不是 JSON 数据面。
    problems.push({ code: Problem.NOT_AN_OBJECT, field: path });
    ancestors.delete(value);
    return;
  }

  if (isArray && arrayLengthSafe(value) > MAX_ARRAY_LENGTH) {
    problems.push({ code: Problem.NON_JSON_VALUE, field: path });
    ancestors.delete(value);
    return;
  }

  const keys = ownKeysSafe(value);
  if (keys === null) {
    problems.push({ code: Problem.UNREADABLE_RECORD, field: path });
  } else {
    for (const key of keys) {
      const desc = getOwnPropertyDescriptorSafe(value, key);
      if (!desc || !desc.enumerable) continue; // 非枚举属性（如数组 length）不参与数据面。

      const childPath =
        path === "" ? key : isArray && isArrayIndexKey(key) ? `${path}[${key}]` : `${path}.${key}`;

      if (DANGEROUS_KEYS.has(key)) {
        problems.push({ code: Problem.DANGEROUS_KEY, field: childPath });
        continue;
      }
      if (!isDataDescriptor(desc)) {
        problems.push({ code: Problem.ACCESSOR_PROPERTY, field: childPath });
        continue;
      }
      validateJsonValue(desc.value, childPath, ancestors, depth + 1, problems);
    }
  }

  ancestors.delete(value);
}

function dedupeProblems(problems) {
  const seen = new Set();
  const out = [];
  for (const p of problems) {
    const tag = `${p.code} ${p.field ?? ""}`;
    if (!seen.has(tag)) {
      seen.add(tag);
      out.push(p);
    }
  }
  return out;
}

/**
 * 校验单条事件信封，返回结构化结果，绝不抛错。
 * @param {*} record 合作方提交的原始记录（可能为 null、数组、被污染对象或代理）
 * @returns {{ valid: boolean, problems: Array<{code: string, field?: string}> }}
 */
export function validateEventDetailed(record) {
  if (record === null || record === undefined) {
    return { valid: false, problems: [{ code: Problem.EMPTY_RECORD }] };
  }
  if (typeof record !== "object") {
    return { valid: false, problems: [{ code: Problem.NOT_AN_OBJECT }] };
  }
  const topLevelArray = isArraySafe(record);
  if (topLevelArray === null) {
    return { valid: false, problems: [{ code: Problem.UNREADABLE_RECORD }] };
  }
  if (topLevelArray) {
    // 单条信封不接受数组（数组只允许出现在 payload 内部）。
    return { valid: false, problems: [{ code: Problem.ARRAY_REJECTED }] };
  }

  const proto = getPrototypeOfSafe(record);
  if (!proto.ok) {
    // getPrototypeOf 都抛错（恶意 Proxy）—— 整条不可读，隔离。
    return { valid: false, problems: [{ code: Problem.UNREADABLE_RECORD }] };
  }
  if (proto.value !== Object.prototype && proto.value !== null) {
    // 原型不是标准 Object.prototype（被替换 / 类实例 / 外来宿主对象）。
    // 注意：全局 Object.prototype 被污染后原型身份不变，因此危险键与自身属性
    // 检查才是关键防线 —— 继承来的字段一律不可见。
    return { valid: false, problems: [{ code: Problem.PROTOTYPE_POLLUTED }] };
  }

  // ownKeys 都无法获取时，整条记录不可信，直接隔离。
  if (ownKeysSafe(record) === null) {
    return { valid: false, problems: [{ code: Problem.UNREADABLE_RECORD }] };
  }

  const problems = [];

  // 必填字段：必须是对象“自身拥有”的可枚举数据属性。不再使用 `in`，
  // 因此原型链上的 event_id（污染或恶意挂载）不会被当作真实数据。
  for (const name of REQUIRED_FIELDS) {
    const desc = getOwnPropertyDescriptorSafe(record, name);
    if (!desc || !desc.enumerable || !isDataDescriptor(desc)) {
      problems.push({ code: Problem.MISSING_FIELD, field: name });
    }
  }

  const kindDesc = getOwnPropertyDescriptorSafe(record, "kind");
  if (kindDesc && kindDesc.enumerable && isDataDescriptor(kindDesc)) {
    if (!EVENT_KINDS.includes(kindDesc.value)) {
      problems.push({ code: Problem.UNKNOWN_KIND, field: "kind" });
    }
  }

  // 深度遍历：循环结构、非 JSON 值、嵌套危险键/访问器。
  validateJsonValue(record, "", new Set(), 0, problems);

  const unique = dedupeProblems(problems);
  return { valid: unique.length === 0, problems: unique };
}

/**
 * 旧契约兼容入口：合法记录返回 []（与旧版完全一致），非法记录返回问题标识数组。
 * 旧版能识别的问题仍输出字段名（如 "event_id" / "kind"），旧版无法处理的新结构
 * 问题输出稳定代码（如 "EMPTY_RECORD" / "DANGEROUS_KEY:__proto__"）。
 */
export function validateEvent(record) {
  return validateEventDetailed(record).problems.map((p) => {
    if (p.code === Problem.MISSING_FIELD) return p.field;
    if (p.code === Problem.UNKNOWN_KIND) return "kind";
    return p.field ? `${p.code}:${p.field}` : p.code;
  });
}

// ---------------------------------------------------------------------------
// 安全序列化与规范化摘要
// ---------------------------------------------------------------------------

function unsafeValueError(code, path) {
  const err = new TypeError(`${code} at ${path || "<root>"}`);
  err.code = code;
  return err;
}

// 与校验器共用同一套“只看自身可枚举数据属性”的遍历逻辑；绝不触碰原型，
// 因此挂载在原型上的敏感值不会出现在输出里。
function buildCanonical(value, path, ancestors, depth) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw unsafeValueError(Problem.NON_JSON_VALUE, path);
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw unsafeValueError(Problem.NON_JSON_VALUE, path);
  }
  if (depth > MAX_DEPTH) throw unsafeValueError(Problem.NON_JSON_VALUE, path);
  if (ancestors.has(value)) throw unsafeValueError(Problem.CIRCULAR_STRUCTURE, path);
  ancestors.add(value);

  let out;
  const isArray = isArraySafe(value);
  if (isArray === null) throw unsafeValueError(Problem.UNREADABLE_RECORD, path);
  if (isArray) {
    const length = arrayLengthSafe(value);
    if (length > MAX_ARRAY_LENGTH) throw unsafeValueError(Problem.NON_JSON_VALUE, path);
    const parts = [];
    for (let i = 0; i < length; i++) {
      const desc = getOwnPropertyDescriptorSafe(value, String(i));
      // 稀疏数组空洞按 JSON 惯例序列化为 null。
      parts.push(
        desc && isDataDescriptor(desc)
          ? buildCanonical(desc.value, `${path}[${i}]`, ancestors, depth + 1)
          : "null",
      );
    }
    out = `[${parts.join(",")}]`;
  } else {
    if (!isPlainJsonObject(value)) throw unsafeValueError(Problem.NOT_AN_OBJECT, path);
    const keys = ownKeysSafe(value);
    if (keys === null) throw unsafeValueError(Problem.UNREADABLE_RECORD, path);
    const dataKeys = keys
      .filter((key) => {
        if (DANGEROUS_KEYS.has(key)) return false;
        const desc = getOwnPropertyDescriptorSafe(value, key);
        return !!desc && desc.enumerable && isDataDescriptor(desc);
      })
      .sort();
    const parts = dataKeys.map((key) => {
      const desc = getOwnPropertyDescriptorSafe(value, key);
      const childPath = path === "" ? key : `${path}.${key}`;
      return `${JSON.stringify(key)}:${buildCanonical(desc.value, childPath, ancestors, depth + 1)}`;
    });
    out = `{${parts.join(",")}}`;
  }

  ancestors.delete(value);
  return out;
}

/**
 * 规范化 JSON 文本：递归排序对象键，只包含自身可枚举数据属性。
 * 键顺序/空白差异不会影响结果；原型与访问器上的任何值都不会被读出。
 * 输入若含循环等非 JSON 结构，抛出带 .code 的 TypeError（调用方应先校验）。
 */
export function canonicalJson(value) {
  return buildCanonical(value, "", new Set(), 0);
}

/** 规范化摘要（sha256），用于按事件标识 + 内容去重。 */
export function canonicalDigest(value) {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

/**
 * 面向日志/错误响应的安全序列化：保证不回显原型上的敏感值、不触发访问器。
 * 已通过校验的记录可直接序列化；未校验对象遇到循环等结构时返回带标记的
 * JSON 字面量，而不是把内部值带出或抛出异常。
 */
export function safeJsonStringify(value) {
  try {
    return canonicalJson(value);
  } catch (err) {
    return JSON.stringify({ _unsafe: String(err.code || "UNSAUDITED_VALUE") });
  }
}
