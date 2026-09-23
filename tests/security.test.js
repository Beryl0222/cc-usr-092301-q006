import assert from "node:assert/strict";
import test from "node:test";
import {
  REQUIRED_FIELDS,
  canonicalJson,
  safeJsonStringify,
  validateEvent,
  validateEventDetailed,
} from "../src/race_medical_dispatch.js";

function makeEvent(overrides = {}) {
  return {
    event_id: "evt-0001",
    kind: "RESOURCE_DECLARED",
    occurred_at: "2026-09-21T08:30:00+08:00",
    subject_id: "team-07",
    payload: { resource: "ambulance", count: 2 },
    ...overrides,
  };
}

test("原型链上的必填字段不被当成真实数据", () => {
  // 生产故障二：旧版用 `in` 判断，污染过的信封会被当成合法数据进入资源审批。
  for (const name of REQUIRED_FIELDS) Object.prototype[name] = "forged";
  Object.prototype.kind = "EVENT_RISK_FILED";
  Object.prototype.payload = {};
  try {
    const envelope = {}; // 自身没有任何字段 —— 旧版 `in` 判断会全部通过
    const problems = validateEvent(envelope);
    assert.deepEqual([...problems].sort(), [...REQUIRED_FIELDS].sort());
  } finally {
    for (const name of REQUIRED_FIELDS) delete Object.prototype[name];
  }
});

test("被替换原型的信封整体拒绝", () => {
  const envelope = Object.create(makeEvent()); // 字段全部挂在自定义原型上
  assert.deepEqual(validateEvent(envelope), ["PROTOTYPE_POLLUTED"]);
});

test("JSON 中的 __proto__ 键被拒绝且不造成污染", () => {
  const record = JSON.parse(
    '{"event_id":"e1","kind":"EVENT_RISK_FILED","occurred_at":"t","subject_id":"s","payload":{"__proto__":{"isAdmin":true}}}',
  );
  const problems = validateEvent(record);
  assert.ok(problems.some((p) => p.startsWith("DANGEROUS_KEY")));
  assert.equal({}.isAdmin, undefined);
});

test("constructor 与 prototype 键同样被拒绝", () => {
  assert.ok(
    validateEvent(makeEvent({ payload: { constructor: "x" } })).some((p) =>
      p.startsWith("DANGEROUS_KEY"),
    ),
  );
  assert.ok(
    validateEvent(makeEvent({ payload: { prototype: {} } })).some((p) =>
      p.startsWith("DANGEROUS_KEY"),
    ),
  );
});

test("恶意 getter 不会被执行", () => {
  let calls = 0;
  const record = makeEvent();
  Object.defineProperty(record, "payload", {
    enumerable: true,
    get() {
      calls += 1;
      throw new Error("foreign code executed");
    },
  });
  const problems = validateEvent(record);
  assert.equal(calls, 0);
  assert.ok(problems.some((p) => p.startsWith("ACCESSOR_PROPERTY")));
});

test("payload 内嵌套 getter 同样不被执行", () => {
  let calls = 0;
  const payload = {};
  Object.defineProperty(payload, "note", {
    enumerable: true,
    get() {
      calls += 1;
      return "x";
    },
  });
  const detail = validateEventDetailed(makeEvent({ payload }));
  assert.equal(calls, 0);
  assert.ok(
    detail.problems.some((p) => p.code === "ACCESSOR_PROPERTY" && p.field === "payload.note"),
  );
});

test("原型链上的 getter 不会被执行", () => {
  let calls = 0;
  Object.defineProperty(Object.prototype, "kind", {
    configurable: true,
    get() {
      calls += 1;
      return "EVENT_RISK_FILED";
    },
  });
  try {
    const record = makeEvent();
    delete record.kind;
    const problems = validateEvent(record);
    assert.equal(calls, 0);
    assert.ok(problems.includes("kind"));
  } finally {
    delete Object.prototype.kind;
  }
});

test("循环结构给出确定错误", () => {
  const record = makeEvent();
  record.payload.self = record.payload;
  assert.ok(validateEvent(record).some((p) => p.startsWith("CIRCULAR_STRUCTURE")));

  const viaArray = makeEvent({ payload: { list: [] } });
  viaArray.payload.list.push(viaArray.payload);
  assert.ok(validateEvent(viaArray).some((p) => p.startsWith("CIRCULAR_STRUCTURE")));
});

test("共享引用但不是循环的记录仍然合法", () => {
  const shared = { unit: "medical" };
  assert.deepEqual(validateEvent(makeEvent({ payload: { a: shared, b: shared } })), []);
});

test("非 JSON 值给出确定错误", () => {
  assert.ok(
    validateEvent(makeEvent({ payload: { run: () => {} } })).some((p) =>
      p.startsWith("NON_JSON_VALUE"),
    ),
  );
  assert.ok(
    validateEvent(makeEvent({ payload: { sym: Symbol("s") } })).some((p) =>
      p.startsWith("NON_JSON_VALUE"),
    ),
  );
  assert.ok(
    validateEvent(makeEvent({ payload: { big: 1n } })).some((p) =>
      p.startsWith("NON_JSON_VALUE"),
    ),
  );
  assert.ok(
    validateEvent(makeEvent({ payload: { nan: Number.NaN } })).some((p) =>
      p.startsWith("NON_JSON_VALUE"),
    ),
  );
  assert.ok(
    validateEvent(makeEvent({ payload: { inf: Infinity } })).some((p) =>
      p.startsWith("NON_JSON_VALUE"),
    ),
  );
  assert.ok(
    validateEvent(makeEvent({ payload: { when: new Date(0) } })).some((p) =>
      p.startsWith("NOT_AN_OBJECT"),
    ),
  );
});

test("读取异常转化为确定错误而不是终止", () => {
  const { proxy, revoke } = Proxy.revocable(makeEvent(), {});
  revoke();
  assert.deepEqual(validateEvent(proxy), ["UNREADABLE_RECORD"]);

  const evil = new Proxy(
    {},
    {
      ownKeys() {
        throw new Error("boom");
      },
    },
  );
  assert.deepEqual(validateEvent(evil), ["UNREADABLE_RECORD"]);
});

test("校验不修改输入记录", () => {
  const record = makeEvent();
  const before = JSON.stringify(record);
  validateEvent(record);
  validateEventDetailed(record);
  assert.equal(JSON.stringify(record), before);
});

test("规范化序列化与键顺序无关", () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), canonicalJson({ a: 2, b: 1 }));
  assert.equal(canonicalJson({ a: 2, b: 1 }), '{"a":2,"b":1}');
});

test("safeJsonStringify 对循环结构返回标记而不抛出、不带出内容", () => {
  const record = makeEvent();
  record.payload.self = record;
  const out = safeJsonStringify(record);
  assert.ok(out.includes("CIRCULAR_STRUCTURE"));
  assert.ok(!out.includes("ambulance"));
});

test("序列化不回显原型上的敏感值", () => {
  const secret = "proto-secret-value";
  Object.prototype.leaked = secret;
  try {
    const record = makeEvent({ event_id: "evt-ser" });
    const canonical = canonicalJson(record);
    const safe = safeJsonStringify(record);
    assert.ok(!canonical.includes(secret));
    assert.ok(!safe.includes(secret));
    assert.ok(!canonical.includes("leaked"));
    // 与无污染环境下的输出完全一致
    assert.equal(canonical, canonicalJson(makeEvent({ event_id: "evt-ser" })));
  } finally {
    delete Object.prototype.leaked;
  }
});
