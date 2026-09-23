import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  EVENT_KINDS,
  ProblemCode,
  canonicalDigest,
  createInbox,
  toErrorResponse,
  validateEvent,
} from "../src/race_medical_dispatch.js";

const sampleUrl = new URL("../data/sample.json", import.meta.url);

async function readSample() {
  return JSON.parse(await readFile(sampleUrl, "utf8"));
}

// 正常医疗资源事件的规范化摘要指纹（键序无关）；改动正常事件输出会立刻可见。
const GOLDEN_SAMPLE_DIGEST =
  "1efc3b084c711472fb52957dd4123feab61f1e8e1ea17ba5d60264b8e8ae305f";

function validEvent(overrides = {}) {
  return {
    event_id: "evt-1",
    kind: "RESOURCE_DECLARED",
    occurred_at: "2026-09-20T09:00:00+08:00",
    subject_id: "station-7",
    payload: { resource: "AED", count: 2, note: "虚构医疗资源事件" },
    ...overrides,
  };
}

function codes(problems) {
  return problems.map((item) => item.code);
}

// ---- 兼容性：旧样例与事件名称保持可用 ----

test("样例符合领域约定（旧合同输出不变）", async () => {
  const record = await readSample();
  assert.deepEqual(validateEvent(record), []);
});

test("全部五种事件名称仍然合法", () => {
  for (const kind of EVENT_KINDS) {
    assert.deepEqual(validateEvent(validEvent({ kind })), []);
  }
});

test("正常事件的规范化摘要与黄金指纹一致", async () => {
  const record = await readSample();
  const { digest, problems } = canonicalDigest(record);
  assert.deepEqual(problems, []);
  assert.equal(digest, GOLDEN_SAMPLE_DIGEST);
});

test("键顺序不同的同一事件摘要相同（规范化输出）", () => {
  const a = validEvent();
  const b = {
    payload: { count: 2, note: "虚构医疗资源事件", resource: "AED" },
    subject_id: "station-7",
    occurred_at: "2026-09-20T09:00:00+08:00",
    kind: "RESOURCE_DECLARED",
    event_id: "evt-1",
  };
  assert.equal(canonicalDigest(a).digest, canonicalDigest(b).digest);
});

// ---- 空记录：不再让校验函数终止 ----

test("空记录产生确定性错误而不是抛异常", () => {
  assert.deepEqual(validateEvent(null), [
    { code: ProblemCode.NOT_RECORD, path: "$" },
  ]);
  assert.deepEqual(validateEvent(undefined), [
    { code: ProblemCode.NOT_RECORD, path: "$" },
  ]);
  assert.equal(codes(validateEvent(42))[0], ProblemCode.NOT_RECORD);
  assert.equal(codes(validateEvent("x"))[0], ProblemCode.NOT_RECORD);
});

test("数组不能冒充记录", () => {
  assert.deepEqual(codes(validateEvent([])), [ProblemCode.ARRAY_RECORD]);
});

// ---- 原型污染：只承认对象自身拥有的字段 ----

test("必填字段只存在于原型链上时判为缺失", () => {
  const proto = {
    event_id: "from-proto",
    kind: "RESOURCE_DECLARED",
    occurred_at: "2026-09-20T09:00:00+08:00",
    subject_id: "station-7",
    payload: {},
  };
  const record = Object.create(proto);
  const problems = validateEvent(record);
  for (const field of [
    "event_id",
    "kind",
    "occurred_at",
    "subject_id",
    "payload",
  ]) {
    assert.ok(
      problems.some(
        (item) =>
          item.code === ProblemCode.MISSING_FIELD && item.path === field,
      ),
      `${field} 不应从原型链被承认`,
    );
  }
});

test("非普通原型的对象直接判定为原型污染", () => {
  const record = Object.create(null);
  Object.assign(record, validEvent());
  // Object.create(null) 是可接受的 JSON 风格字典……
  assert.deepEqual(validateEvent(record), []);

  class Evil {}
  const evil = new Evil();
  Object.assign(evil, validEvent());
  assert.deepEqual(codes(validateEvent(evil)), [
    ProblemCode.PROTOTYPE_POLLUTION,
  ]);
});

test("自有危险键 __proto__/constructor/prototype 被拒绝", () => {
  // JSON.parse 对 __proto__ 使用 defineProperty 语义，会形成自有数据属性。
  const parsed = JSON.parse(
    '{"event_id":"e1","kind":"RESOURCE_DECLARED","occurred_at":"2026-09-20T09:00:00+08:00","subject_id":"s1","payload":{},"__proto__":{"polluted":true}}',
  );
  assert.ok(
    Object.prototype.hasOwnProperty.call(parsed, "__proto__"),
    "测试前置：__proto__ 是自有属性",
  );
  assert.ok(codes(validateEvent(parsed)).includes(ProblemCode.DANGEROUS_KEY));

  for (const key of ["constructor", "prototype"]) {
    const record = validEvent({ [key]: { x: 1 } });
    assert.ok(
      codes(validateEvent(record)).includes(ProblemCode.DANGEROUS_KEY),
      `${key} 应被拒绝`,
    );
  }
});

test("嵌套危险键同样被拒绝", () => {
  const record = validEvent({ payload: { nested: { constructor: 1 } } });
  const problems = validateEvent(record);
  assert.ok(
    problems.some(
      (item) =>
        item.code === ProblemCode.DANGEROUS_KEY &&
        item.path === "$.payload.nested.constructor",
    ),
  );
});

test("Object.prototype 被污染期间也不承认继承字段", () => {
  const record = { ...validEvent() };
  delete record.event_id;
  Object.prototype.event_id = "PROTO-SECRET";
  try {
    const problems = validateEvent(record);
    assert.ok(
      problems.some(
        (item) =>
          item.code === ProblemCode.MISSING_FIELD &&
          item.path === "event_id",
      ),
    );
    assert.ok(!JSON.stringify(problems).includes("PROTO-SECRET"));
  } finally {
    delete Object.prototype.event_id;
  }
});

// ---- 恶意访问器与不可读代理：永不执行外来代码 ----

test("getter 不会被执行，并报告访问器属性", () => {
  let calls = 0;
  const record = validEvent();
  Object.defineProperty(record, "event_id", {
    enumerable: true,
    get() {
      calls += 1;
      throw new Error("外来代码被执行了");
    },
  });
  const problems = validateEvent(record);
  assert.equal(calls, 0, "getter 一次都不能被调用");
  assert.ok(
    problems.some(
      (item) =>
        item.code === ProblemCode.ACCESSOR_PROPERTY &&
        item.path === "$.event_id",
    ),
  );
  assert.ok(
    problems.some(
      (item) =>
        item.code === ProblemCode.MISSING_FIELD &&
        item.path === "event_id",
    ),
  );
});

test("原型上的敏感 getter 不会被触发或回显", () => {
  let calls = 0;
  const secretProto = {
    event_id: "from-proto",
    kind: "RESOURCE_DECLARED",
    occurred_at: "2026-09-20T09:00:00+08:00",
    subject_id: "station-7",
    payload: {},
  };
  Object.defineProperty(secretProto, "ssn", {
    enumerable: true,
    get() {
      calls += 1;
      return "SSN-SECRET-MUST-NOT-LEAK";
    },
  });
  const record = Object.create(secretProto);
  const inbox = createInbox();
  const result = inbox.receive([record]);
  assert.equal(calls, 0);
  assert.equal(result.accepted.length, 0);
  assert.equal(result.rejected.length, 1);
  const response = JSON.stringify(toErrorResponse(result));
  assert.ok(!response.includes("SSN-SECRET-MUST-NOT-LEAK"));
  assert.ok(!response.includes("from-proto"));
});

test("读取时抛异常的代理被隔离为不可读对象", () => {
  const throwingProxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error("代理陷阱爆炸");
      },
    },
  );
  assert.deepEqual(codes(validateEvent(throwingProxy)), [
    ProblemCode.UNREADABLE_OBJECT,
  ]);

  const keyProxy = new Proxy(
    { a: 1 },
    {
      ownKeys() {
        throw new Error("ownKeys 爆炸");
      },
    },
  );
  assert.deepEqual(codes(validateEvent(keyProxy)), [
    ProblemCode.UNREADABLE_OBJECT,
  ]);
});

test("嵌套在 payload 里的恶意代理被确定性处理", () => {
  // get 陷阱从不被调用（全程只读描述符）：该代理等价于无自有键的空对象。
  const throwingGet = validEvent({
    payload: {
      hostile: new Proxy(
        {},
        {
          get() {
            throw new Error("不应被触发");
          },
        },
      ),
    },
  });
  assert.deepEqual(validateEvent(throwingGet), []);

  // getPrototypeOf 抛错的代理无法安全判定，整条记录被拒绝。
  const throwingProto = validEvent({
    payload: {
      hostile: new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error("boom");
          },
        },
      ),
    },
  });
  assert.ok(
    codes(validateEvent(throwingProto)).includes(
      ProblemCode.UNREADABLE_OBJECT,
    ),
  );
});

// ---- 循环结构与非 JSON 值 ----

test("循环引用被确定地拒绝", () => {
  const record = validEvent();
  record.payload.self = record;
  assert.ok(
    codes(validateEvent(record)).includes(ProblemCode.CIRCULAR_STRUCTURE),
  );

  const direct = { a: 1 };
  direct.loop = direct;
  assert.ok(
    codes(validateEvent(direct)).includes(ProblemCode.CIRCULAR_STRUCTURE),
  );
});

test("NaN/Infinity/函数等非 JSON 值被拒绝", () => {
  assert.ok(
    codes(validateEvent(validEvent({ payload: { n: NaN } }))).includes(
      ProblemCode.INVALID_JSON_VALUE,
    ),
  );
  assert.ok(
    codes(validateEvent(validEvent({ payload: { n: Infinity } }))).includes(
      ProblemCode.INVALID_JSON_VALUE,
    ),
  );
});

// ---- 必填字段类型与事件名 ----

test("非法事件名报错且不回显原值", () => {
  const problems = validateEvent(validEvent({ kind: "SECRET_KIND_XYZ" }));
  assert.ok(codes(problems).includes(ProblemCode.INVALID_KIND));
  assert.ok(!JSON.stringify(problems).includes("SECRET_KIND_XYZ"));
});

test("时间戳与标量字段类型被校验", () => {
  assert.ok(
    codes(validateEvent(validEvent({ occurred_at: "not-a-date" }))).includes(
      ProblemCode.INVALID_FIELD,
    ),
  );
  assert.ok(
    codes(validateEvent(validEvent({ event_id: 123 }))).includes(
      ProblemCode.INVALID_FIELD,
    ),
  );
  assert.ok(
    codes(validateEvent(validEvent({ payload: [] }))).includes(
      ProblemCode.INVALID_FIELD,
    ),
  );
});

// ---- 混合批次：结果与原序号绑定，单条异常被隔离 ----

test("混合批次中每条结果都与原序号绑定", () => {
  const good1 = validEvent({ event_id: "evt-good-1" });
  const good2 = validEvent({ event_id: "evt-good-2" });
  const polluted = Object.create(
    Object.assign(
      Object.create(null),
      {
        event_id: "proto",
        kind: "RESOURCE_DECLARED",
        occurred_at: "2026-09-20T09:00:00+08:00",
        subject_id: "s",
        payload: {},
      },
    ),
  );
  const getterBomb = validEvent({ event_id: "evt-bomb" });
  let calls = 0;
  Object.defineProperty(getterBomb, "kind", {
    enumerable: true,
    get() {
      calls += 1;
      throw new Error("boom");
    },
  });
  const proxyBomb = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error("boom");
      },
    },
  );

  const inbox = createInbox();
  const result = inbox.receive([
    good1, // 0 接受
    null, // 1 拒绝：空记录
    polluted, // 2 拒绝：字段全在原型上
    good2, // 3 接受（前一条失败不影响）
    getterBomb, // 4 拒绝：访问器
    proxyBomb, // 5 拒绝：不可读
  ]);

  assert.deepEqual(
    result.accepted.map((item) => item.index),
    [0, 3],
  );
  assert.deepEqual(
    result.rejected.map((item) => item.index),
    [1, 2, 4, 5],
  );
  assert.equal(calls, 0);
  assert.equal(inbox.size(), 2);

  const byIndex = new Map(result.rejected.map((item) => [item.index, item]));
  assert.deepEqual(codes(byIndex.get(1).problems), [ProblemCode.NOT_RECORD]);
  assert.ok(codes(byIndex.get(2).problems).includes(ProblemCode.MISSING_FIELD));
  assert.ok(
    codes(byIndex.get(4).problems).includes(ProblemCode.ACCESSOR_PROPERTY),
  );
  assert.ok(
    codes(byIndex.get(5).problems).includes(ProblemCode.UNREADABLE_OBJECT),
  );
});

test("单条读取异常不会中断后续记录处理", () => {
  const inbox = createInbox();
  const result = inbox.receive([
    new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("boom");
        },
      },
    ),
    validEvent({ event_id: "evt-after-throw" }),
  ]);
  assert.equal(result.rejected[0].index, 0);
  assert.equal(result.accepted[0].index, 1);
  assert.equal(result.accepted[0].event_id, "evt-after-throw");
});

// ---- 重放去重与冲突 ----

test("相同事件重放按事件标识与规范化摘要去重", () => {
  const inbox = createInbox();
  const first = inbox.receive([validEvent()]);
  assert.equal(first.accepted.length, 1);

  const replay = inbox.receive([
    {
      // 键序不同、等价 JSON
      payload: { note: "虚构医疗资源事件", count: 2, resource: "AED" },
      event_id: "evt-1",
      kind: "RESOURCE_DECLARED",
      occurred_at: "2026-09-20T09:00:00+08:00",
      subject_id: "station-7",
    },
  ]);
  assert.equal(replay.accepted.length, 0);
  assert.equal(replay.duplicates.length, 1);
  assert.equal(replay.duplicates[0].index, 0);
  assert.equal(replay.duplicates[0].event_id, "evt-1");
  assert.equal(inbox.size(), 1);
});

test("同标识不同内容的重放形成冲突，不静默采用任何版本", () => {
  const inbox = createInbox();
  const first = validEvent({ payload: { resource: "AED", count: 2 } });
  const altered = validEvent({ payload: { resource: "AED", count: 99 } });

  const r1 = inbox.receive([first]);
  const r2 = inbox.receive([altered]);
  assert.equal(r1.accepted.length, 1);
  assert.equal(r2.accepted.length, 0);
  assert.equal(r2.duplicates.length, 0);
  assert.equal(r2.conflicts.length, 1);

  const conflict = r2.conflicts[0];
  assert.equal(conflict.event_id, "evt-1");
  assert.equal(conflict.first_index, 0);
  assert.equal(conflict.index, 0);
  assert.notEqual(conflict.stored_digest, conflict.received_digest);

  const conflicts = inbox.listConflicts();
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].stored_digest, r1.accepted[0].digest);

  // 已存版本保持不变：重放原始版本仍是去重，重放变异版本仍是冲突。
  const r3 = inbox.receive([first]);
  assert.equal(r3.duplicates.length, 1);
  assert.equal(r3.conflicts.length, 0);
  const r4 = inbox.receive([altered]);
  assert.equal(r4.conflicts.length, 1);
  assert.equal(inbox.size(), 1, "冲突期间存储数不应变化");
});

test("一批内多个相同记录只接受一次，其余为重复", () => {
  const inbox = createInbox();
  const result = inbox.receive([
    validEvent({ event_id: "evt-x" }),
    validEvent({ event_id: "evt-x" }),
    validEvent({ event_id: "evt-x", payload: { different: true } }),
  ]);
  assert.equal(result.accepted.length, 1);
  assert.equal(result.duplicates.length, 1);
  assert.equal(result.conflicts.length, 1);
});

// ---- 并发接收 ----

test("并发接收相同事件恰好接受一次", async () => {
  const inbox = createInbox();
  const batches = await Promise.all(
    Array.from({ length: 10 }, () => inbox.receive([validEvent()])),
  );
  const accepted = batches.reduce((n, r) => n + r.accepted.length, 0);
  const duplicated = batches.reduce((n, r) => n + r.duplicates.length, 0);
  assert.equal(accepted, 1);
  assert.equal(duplicated, 9);
  assert.equal(inbox.size(), 1);
});

test("并发接收同标识不同内容只接受首个，其余全部进冲突", async () => {
  const inbox = createInbox();
  const variants = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      inbox.receive([validEvent({ payload: { count: i } })]),
    ),
  );
  const accepted = variants.reduce((n, r) => n + r.accepted.length, 0);
  const conflicted = variants.reduce((n, r) => n + r.conflicts.length, 0);
  assert.equal(accepted, 1);
  assert.equal(conflicted, 7);
  assert.equal(inbox.size(), 1);
  assert.equal(inbox.listConflicts().length, 7);
});

// ---- 错误响应与日志不泄露内容 ----

test("错误响应只含序号、安全标识、错误码与摘要", () => {
  const secretRecord = Object.create({ ssn: "SSN-ON-PROTO" });
  Object.assign(
    secretRecord,
    validEvent({ event_id: "evt-safe-id", kind: "BOGUS_KIND" }),
  );
  // kind 合法化以便走到“原型污染”之外的场景：这里直接构造缺字段记录。
  const missing = { kind: "RESOURCE_DECLARED", secret: "FIELD-SECRET-9" };
  const inbox = createInbox();
  const result = inbox.receive([secretRecord, missing]);
  const response = toErrorResponse(result);
  const text = JSON.stringify(response);

  assert.ok(!text.includes("SSN-ON-PROTO"));
  assert.ok(!text.includes("FIELD-SECRET-9"));
  assert.ok(!text.includes("BOGUS_KIND"));
  assert.equal(response.rejected.length, 2);
  assert.equal(response.rejected[0].event_id, "evt-safe-id");
  for (const item of response.rejected) {
    assert.equal(typeof item.index, "number");
    for (const problem of item.problems) {
      assert.equal(typeof problem.code, "string");
      assert.equal(typeof problem.path, "string");
    }
  }
});

test("日志只记录阶段、序号、标识与摘要，不含记录内容", () => {
  const entries = [];
  const inbox = createInbox({ log: (entry) => entries.push(entry) });
  inbox.receive([
    validEvent({ event_id: "evt-log", payload: { secret: "LOG-SECRET-1" } }),
  ]);
  inbox.receive([
    validEvent({ event_id: "evt-log", payload: { secret: "LOG-SECRET-1" } }),
  ]);
  const text = JSON.stringify(entries);
  assert.ok(!text.includes("LOG-SECRET-1"));
  assert.deepEqual(
    entries.map((entry) => entry.stage),
    ["accepted", "duplicate"],
  );
});

test("接收非数组输入抛出类型错误", () => {
  const inbox = createInbox();
  assert.throws(() => inbox.receive(validEvent()), TypeError);
});

// ---- 正常医疗资源事件的端到端输出 ----

test("正常医疗资源事件端到端输出保持稳定", async () => {
  const sample = await readSample();
  const inbox = createInbox();
  const result = inbox.receive([sample]);
  assert.equal(result.accepted.length, 1);
  assert.deepEqual(result.duplicates, []);
  assert.deepEqual(result.conflicts, []);
  assert.deepEqual(result.rejected, []);
  const accepted = result.accepted[0];
  assert.equal(accepted.event_id, "sample-002-001");
  assert.equal(accepted.kind, "EVENT_RISK_FILED");
  assert.equal(accepted.index, 0);
  assert.equal(accepted.digest, GOLDEN_SAMPLE_DIGEST);

  const replay = inbox.receive([sample]);
  assert.equal(replay.duplicates.length, 1);
  assert.equal(replay.accepted.length, 0);

  const response = toErrorResponse(result);
  assert.deepEqual(response, { rejected: [], conflicts: [] });
});
