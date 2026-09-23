// 群众赛事医疗调度的事件合同校验与接收。
//
// 安全约定：
// - 只承认普通 JSON 对象（[[Prototype]] 为 Object.prototype 或 null）自身的
//   可枚举数据属性；继承自原型链的字段一律不算数；
// - 全程只读取属性描述符，永不调用 getter/setter，也不对外来对象使用
//   JSON.stringify（避免触发 toJSON 等外来代码）；
// - 空值、数组、危险键、访问器属性、循环结构等都产出确定性错误码；
// - 单条记录的任何读取异常只隔离该条，不影响同批其他记录。

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

// 确定性错误码：错误响应与日志只暴露 code/path，不回显记录内容。
export const ProblemCode = Object.freeze({
  NOT_RECORD: "not_record", // null/undefined/原始值
  ARRAY_RECORD: "array_record", // 记录必须是对象，不接受数组
  PROTOTYPE_POLLUTION: "prototype_pollution", // 原型链不是普通对象原型
  DANGEROUS_KEY: "dangerous_key", // __proto__ / constructor / prototype 自有键
  ACCESSOR_PROPERTY: "accessor_property", // getter/setter，永不执行
  NON_JSON_KEY: "non_json_key", // symbol 等 JSON 不可能出现的键
  UNREADABLE_OBJECT: "unreadable_object", // 代理/陷阱在读取时抛异常
  MISSING_FIELD: "missing_field", // 必填的自有字段不存在
  INVALID_FIELD: "invalid_field", // 必填字段类型/取值不合法
  INVALID_KIND: "invalid_kind", // 事件名称不在领域约定内
  INVALID_JSON_VALUE: "invalid_json_value", // 函数/symbol/NaN 等非 JSON 值
  CIRCULAR_STRUCTURE: "circular_structure", // 循环引用，无法安全序列化
});

const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const INVALID = Symbol("invalid_snapshot_node");
const ROOT = "$";

const hasOwn = Function.prototype.call.bind(Object.prototype.hasOwnProperty);

function problem(code, path) {
  return { code, path };
}

function isAccessor(descriptor) {
  return (
    descriptor !== undefined &&
    descriptor !== null &&
    (typeof descriptor.get === "function" ||
      typeof descriptor.set === "function")
  );
}

function joinPath(path, key) {
  return path === ROOT ? `${ROOT}.${key}` : `${path}.${key}`;
}

function isPlainPrototype(proto) {
  return proto === Object.prototype || proto === null;
}

// 安全地把外来值克隆为纯 JSON 快照：只走自有可枚举数据属性，
// 访问器不执行、危险键不拷贝、循环引用被识别。所有问题收集到 problems。
function evaluate(raw) {
  const problems = [];

  if (raw === null || typeof raw !== "object") {
    return { snapshot: null, problems: [problem(ProblemCode.NOT_RECORD, ROOT)] };
  }
  if (Array.isArray(raw)) {
    return { snapshot: null, problems: [problem(ProblemCode.ARRAY_RECORD, ROOT)] };
  }

  let rootProto;
  try {
    rootProto = Object.getPrototypeOf(raw);
  } catch {
    return {
      snapshot: null,
      problems: [problem(ProblemCode.UNREADABLE_OBJECT, ROOT)],
    };
  }

  // 根键在进入遍历前先探测一次：根对象自身都不可枚举时，
  // 不再产生任何字段级诊断，只给单一的 UNREADABLE_OBJECT。
  let rootKeys;
  try {
    rootKeys = Reflect.ownKeys(raw);
  } catch {
    return {
      snapshot: null,
      problems: [problem(ProblemCode.UNREADABLE_OBJECT, ROOT)],
    };
  }

  const active = new WeakSet();

  const cloneNode = (value, path, allowArray, knownProto, knownKeys) => {
    if (value === null) return null;
    const type = typeof value;
    if (type === "string" || type === "boolean") return value;
    if (type === "number") {
      if (Number.isFinite(value)) return value;
      problems.push(problem(ProblemCode.INVALID_JSON_VALUE, path));
      return INVALID;
    }
    if (type !== "object") {
      // 函数、symbol、undefined、bigint 都不是可传输的 JSON 值。
      problems.push(problem(ProblemCode.INVALID_JSON_VALUE, path));
      return INVALID;
    }

    if (active.has(value)) {
      problems.push(problem(ProblemCode.CIRCULAR_STRUCTURE, path));
      return INVALID;
    }

    if (Array.isArray(value)) {
      if (!allowArray) {
        problems.push(problem(ProblemCode.ARRAY_RECORD, path));
        return INVALID;
      }
      active.add(value);
      try {
        let length;
        try {
          const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
          length =
            lengthDescriptor &&
            "value" in lengthDescriptor &&
            Number.isInteger(lengthDescriptor.value)
              ? lengthDescriptor.value
              : null;
        } catch {
          length = null;
        }
        if (length === null || length < 0) {
          problems.push(problem(ProblemCode.UNREADABLE_OBJECT, path));
          return INVALID;
        }
        const out = new Array(length);
        for (let i = 0; i < length; i += 1) {
          const indexKey = String(i);
          let descriptor;
          try {
            descriptor = Object.getOwnPropertyDescriptor(value, indexKey);
          } catch {
            problems.push(
              problem(ProblemCode.UNREADABLE_OBJECT, `${path}[${i}]`),
            );
            out[i] = null;
            continue;
          }
          if (!descriptor) {
            out[i] = null; // 数组空洞按 JSON 语义记 null
            continue;
          }
          if (isAccessor(descriptor)) {
            problems.push(
              problem(ProblemCode.ACCESSOR_PROPERTY, `${path}[${i}]`),
            );
            out[i] = null;
            continue;
          }
          const cloned = cloneNode(descriptor.value, `${path}[${i}]`, true);
          out[i] = cloned === INVALID ? null : cloned;
        }
        return out;
      } finally {
        active.delete(value);
      }
    }

    let proto;
    if (knownProto !== undefined) {
      proto = knownProto; // 根原型已在遍历前探测
    } else {
      try {
        proto = Object.getPrototypeOf(value);
      } catch {
        problems.push(problem(ProblemCode.UNREADABLE_OBJECT, path));
        return INVALID;
      }
    }
    const pollutedPrototype = !isPlainPrototype(proto);
    if (pollutedPrototype) {
      // 记录污染问题，但继续只克隆自有键，保证诊断完整；最终快照仍会作废。
      problems.push(problem(ProblemCode.PROTOTYPE_POLLUTION, path));
    }

    active.add(value);
    try {
      let keys;
      if (knownKeys !== undefined) {
        keys = knownKeys; // 根键已在遍历前探测
      } else {
        try {
          keys = Reflect.ownKeys(value);
        } catch {
          problems.push(problem(ProblemCode.UNREADABLE_OBJECT, path));
          return INVALID;
        }
      }

      const out = {};
      for (const key of keys) {
        if (typeof key === "symbol") {
          problems.push(problem(ProblemCode.NON_JSON_KEY, `${path}[symbol]`));
          continue;
        }
        if (DANGEROUS_KEYS.has(key)) {
          problems.push(problem(ProblemCode.DANGEROUS_KEY, joinPath(path, key)));
          continue;
        }
        let descriptor;
        try {
          descriptor = Object.getOwnPropertyDescriptor(value, key);
        } catch {
          problems.push(
            problem(ProblemCode.UNREADABLE_OBJECT, joinPath(path, key)),
          );
          continue;
        }
        if (!descriptor) continue;
        if (isAccessor(descriptor)) {
          problems.push(
            problem(ProblemCode.ACCESSOR_PROPERTY, joinPath(path, key)),
          );
          continue;
        }
        if (descriptor.enumerable === false) continue; // 非枚举自有属性不进入合同
        const childPath = joinPath(path, key);
        const cloned = cloneNode(descriptor.value, childPath, true);
        if (cloned !== INVALID) out[key] = cloned;
      }
      return out;
    } finally {
      active.delete(value);
    }
  };

  const snapshot = cloneNode(raw, ROOT, false, rootProto, rootKeys);

  for (const field of REQUIRED_FIELDS) {
    if (!hasOwn(snapshot, field)) {
      problems.push(problem(ProblemCode.MISSING_FIELD, field));
    }
  }

  if (hasOwn(snapshot, "kind")) {
    const kind = snapshot.kind;
    if (typeof kind !== "string" || !EVENT_KINDS.includes(kind)) {
      problems.push(problem(ProblemCode.INVALID_KIND, "kind"));
    }
  }

  for (const field of ["event_id", "subject_id"]) {
    if (hasOwn(snapshot, field) && typeof snapshot[field] !== "string") {
      problems.push(problem(ProblemCode.INVALID_FIELD, field));
    }
  }

  if (
    hasOwn(snapshot, "occurred_at") &&
    (typeof snapshot.occurred_at !== "string" ||
      !Number.isFinite(Date.parse(snapshot.occurred_at)))
  ) {
    problems.push(problem(ProblemCode.INVALID_FIELD, "occurred_at"));
  }

  if (hasOwn(snapshot, "payload")) {
    const payload = snapshot.payload;
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload)
    ) {
      problems.push(problem(ProblemCode.INVALID_FIELD, "payload"));
    }
  }

  // 去重后按 path、code 排序，保证错误输出确定、可比对。
  const unique = new Map();
  for (const item of problems) {
    unique.set(`${item.path} ${item.code}`, item);
  }
  const sorted = [...unique.values()].sort((a, b) => {
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    if (a.code !== b.code) return a.code < b.code ? -1 : 1;
    return 0;
  });

  return { snapshot: sorted.length === 0 ? snapshot : null, problems: sorted };
}

// 保持历史签名：合法记录返回 []，非法记录返回确定性问题列表，且永不抛异常。
export function validateEvent(record) {
  try {
    return evaluate(record).problems;
  } catch {
    return [problem(ProblemCode.UNREADABLE_OBJECT, ROOT)];
  }
}

// 对已校验为纯 JSON 的快照做规范化（键排序）序列化，随后取 SHA-256 摘要。
function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    const body = keys
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",");
    return `{${body}}`;
  }
  return JSON.stringify(value);
}

function digestOf(snapshot) {
  return createHash("sha256")
    .update(stableStringify(snapshot), "utf8")
    .digest("hex");
}

// 对外的单条指纹入口：要么给出摘要，要么给出问题，绝不执行外来代码。
export function canonicalDigest(record) {
  let outcome;
  try {
    outcome = evaluate(record);
  } catch {
    return {
      digest: null,
      problems: [problem(ProblemCode.UNREADABLE_OBJECT, ROOT)],
    };
  }
  if (outcome.problems.length > 0) {
    return { digest: null, problems: outcome.problems };
  }
  return { digest: digestOf(outcome.snapshot), problems: [] };
}

// 在不调用任何访问器的前提下取自有字符串字段（用于拒绝回执里的 event_id）。
function safeOwnString(value, key) {
  try {
    if (value === null || typeof value !== "object") return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor &&
      "value" in descriptor &&
      descriptor.enumerable !== false &&
      typeof descriptor.value === "string"
    ) {
      return descriptor.value;
    }
  } catch {
    // 代理陷阱抛异常时退化为不带标识的回执。
  }
  return undefined;
}

// 创建一个接收信箱：按 event_id + 规范化摘要去重；同标识不同内容进入冲突
// 队列等待人工处理，绝不静默采用任何一个版本。
// ingest 全程同步且不触发任何外来代码，JS 事件循环内单次调用原子完成，
// 因此并发（交错 await）调用 receive 也不会让去重/冲突判定交叉。
export function createInbox({ log = () => {} } = {}) {
  const stored = new Map(); // event_id -> { digest, index, kind }
  const conflicts = [];

  function emit(entry) {
    try {
      log(entry);
    } catch {
      // 日志失败不影响接收主流程。
    }
  }

  function ingest(records) {
    if (!Array.isArray(records)) {
      throw new TypeError("receiveRecords expects an array of records");
    }

    const result = {
      accepted: [],
      duplicates: [],
      conflicts: [],
      rejected: [],
    };

    records.forEach((raw, index) => {
      let outcome;
      try {
        outcome = evaluate(raw);
      } catch {
        outcome = {
          snapshot: null,
          problems: [problem(ProblemCode.UNREADABLE_OBJECT, ROOT)],
        };
      }

      const rawEventId = safeOwnString(raw, "event_id") ?? null;

      if (outcome.problems.length > 0) {
        const entry = {
          index,
          event_id: rawEventId,
          problems: outcome.problems,
        };
        result.rejected.push(entry);
        emit({
          stage: "rejected",
          index,
          event_id: rawEventId,
          codes: outcome.problems.map((item) => item.code),
        });
        return;
      }

      const snapshot = outcome.snapshot;
      const digest = digestOf(snapshot);
      const eventId = snapshot.event_id;
      const kind = snapshot.kind;
      const existing = stored.get(eventId);

      if (!existing) {
        stored.set(eventId, { digest, index, kind });
        result.accepted.push({ index, event_id: eventId, kind, digest });
        emit({ stage: "accepted", index, event_id: eventId, kind, digest });
        return;
      }

      if (existing.digest === digest) {
        result.duplicates.push({ index, event_id: eventId, kind, digest });
        emit({ stage: "duplicate", index, event_id: eventId, kind, digest });
        return;
      }

      // 同一 event_id 但规范化摘要不同：记录冲突，保留首次版本不动。
      const conflict = {
        index,
        event_id: eventId,
        kind,
        first_index: existing.index,
        stored_digest: existing.digest,
        received_digest: digest,
      };
      conflicts.push(conflict);
      result.conflicts.push(conflict);
      emit({
        stage: "conflict",
        index,
        event_id: eventId,
        kind,
        stored_digest: existing.digest,
        received_digest: digest,
      });
    });

    return result;
  }

  return {
    // 同步原子完成；配合 await 使用（await 非 thenable 直接放行）同样安全。
    receive(records) {
      return ingest(records);
    },
    listConflicts() {
      return conflicts.slice();
    },
    size() {
      return stored.size;
    },
  };
}

// 构造对外错误响应：只含序号、安全的 event_id、错误码、路径与摘要，
// 不含任何记录内容，原型上的敏感值不可能出现在这里。
export function toErrorResponse(batchResult) {
  return {
    rejected: batchResult.rejected.map((entry) => ({
      index: entry.index,
      event_id: entry.event_id,
      problems: entry.problems.map((item) => ({
        code: item.code,
        path: item.path,
      })),
    })),
    conflicts: batchResult.conflicts.map((entry) => ({
      index: entry.index,
      event_id: entry.event_id,
      first_index: entry.first_index,
      stored_digest: entry.stored_digest,
      received_digest: entry.received_digest,
    })),
  };
}
