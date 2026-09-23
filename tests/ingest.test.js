import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ConflictResolution,
  IngestStatus,
  createEventStore,
} from "../src/event_store.js";
import {
  EVENT_KINDS,
  safeJsonStringify,
  validateEvent,
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

test("混合批次：每条结果绑定原序号，异常只隔离该条", async () => {
  const store = createEventStore();
  const getterRecord = makeEvent({ event_id: "evt-getter" });
  Object.defineProperty(getterRecord, "payload", {
    enumerable: true,
    get() {
      throw new Error("不应执行");
    },
  });
  const { proxy, revoke } = Proxy.revocable(makeEvent({ event_id: "evt-proxy" }), {});
  revoke();

  const batch = [
    makeEvent({ event_id: "evt-1" }),
    null,
    getterRecord,
    makeEvent({ event_id: "evt-2" }),
    proxy,
    makeEvent({ event_id: "evt-1" }), // 与首条同内容 → 重复
  ];
  const results = await store.ingestBatch(batch);

  assert.equal(results.length, 6);
  assert.deepEqual(
    results.map((r) => r.index),
    [0, 1, 2, 3, 4, 5],
  );
  assert.deepEqual(
    results.map((r) => r.status),
    [
      IngestStatus.ACCEPTED,
      IngestStatus.REJECTED,
      IngestStatus.REJECTED,
      IngestStatus.ACCEPTED,
      IngestStatus.REJECTED,
      IngestStatus.DUPLICATE,
    ],
  );
  assert.deepEqual(results[1].problems, [{ code: "EMPTY_RECORD" }]);
  assert.ok(results[2].problems.some((p) => p.code === "ACCESSOR_PROPERTY"));
  assert.ok(results[4].problems.some((p) => p.code === "UNREADABLE_RECORD"));
  // 已通过的记录仍能按事件标识与规范化摘要去重
  assert.equal(results[5].digest, results[0].digest);
  assert.equal(store.size, 2);
});

test("稀疏批次数组的每个序号都有结果", async () => {
  const store = createEventStore();
  // eslint-disable-next-line no-sparse-arrays
  const batch = [makeEvent({ event_id: "a" }), , makeEvent({ event_id: "b" })];
  const results = await store.ingestBatch(batch);
  assert.equal(results.length, 3);
  assert.equal(results[1].index, 1);
  assert.equal(results[1].status, IngestStatus.REJECTED);
  assert.deepEqual(results[1].problems, [{ code: "EMPTY_RECORD" }]);
});

test("ingestBatch 只接受数组", async () => {
  const store = createEventStore();
  await assert.rejects(() => store.ingestBatch("nope"), TypeError);
});

test("规范化摘要：键顺序不同的同一事件判为重复", async () => {
  const store = createEventStore();
  const first = await store.ingestOne({
    event_id: "e1",
    kind: "PLAN_APPROVED",
    occurred_at: "t",
    subject_id: "s",
    payload: { a: 1, b: 2 },
  });
  const second = await store.ingestOne({
    payload: { b: 2, a: 1 },
    subject_id: "s",
    occurred_at: "t",
    kind: "PLAN_APPROVED",
    event_id: "e1",
  });
  assert.equal(first.status, IngestStatus.ACCEPTED);
  assert.equal(second.status, IngestStatus.DUPLICATE);
  assert.equal(first.digest, second.digest);
  assert.match(first.digest, /^[0-9a-f]{64}$/);
  assert.equal(store.size, 1);
});

test("同标识不同内容的重放形成待人工冲突，不静默采用任何版本", async () => {
  const store = createEventStore();
  const v1 = makeEvent({ event_id: "evt-replay", payload: { count: 2 } });
  const v2 = makeEvent({ event_id: "evt-replay", payload: { count: 99 } });

  const r1 = await store.ingestOne(v1);
  const r2 = await store.ingestOne(v2);
  assert.equal(r1.status, IngestStatus.ACCEPTED);
  assert.equal(r2.status, IngestStatus.CONFLICT);
  assert.equal(r2.existingDigest, r1.digest);
  assert.notEqual(r2.digest, r1.digest);

  // 已存版本未被静默覆盖（不采用后到版本）
  assert.equal(store.acceptedEvents()[0].record.payload.count, 2);

  // 冲突进入人工队列，两个版本都可见（不静默丢弃先到/后到任何一方）
  const conflicts = store.pendingConflicts();
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].eventId, "evt-replay");
  assert.equal(conflicts[0].existing.payload.count, 2);
  assert.equal(conflicts[0].incoming.length, 1);
  assert.equal(conflicts[0].incoming[0].record.payload.count, 99);

  // 与原版本一致的重放仍是幂等重复
  const r3 = await store.ingestOne(v1);
  assert.equal(r3.status, IngestStatus.DUPLICATE);

  // 第三种内容登记为同一冲突的新版本
  const v3 = makeEvent({ event_id: "evt-replay", payload: { count: 3 } });
  const r4 = await store.ingestOne(v3);
  assert.equal(r4.status, IngestStatus.CONFLICT);
  assert.equal(store.pendingConflicts()[0].incoming.length, 2);
  assert.equal(store.size, 1);
});

test("人工处理冲突：保留现有版本或采用指定到来版本", async () => {
  const store = createEventStore();
  await store.ingestOne(makeEvent({ event_id: "e1", payload: { count: 1 } }));
  await store.ingestOne(makeEvent({ event_id: "e1", payload: { count: 2 } }));

  assert.equal(store.resolveConflict("e1", ConflictResolution.KEEP_EXISTING), true);
  assert.equal(store.acceptedEvents()[0].record.payload.count, 1);
  assert.equal(store.pendingConflicts().length, 0);

  await store.ingestOne(makeEvent({ event_id: "e1", payload: { count: 3 } }));
  await store.ingestOne(makeEvent({ event_id: "e1", payload: { count: 4 } }));
  // 多个到来版本时必须指定摘要
  assert.throws(() => store.resolveConflict("e1", ConflictResolution.ACCEPT_INCOMING), TypeError);
  const target = store.pendingConflicts()[0].incoming.find((v) => v.record.payload.count === 4);
  assert.equal(store.resolveConflict("e1", ConflictResolution.ACCEPT_INCOMING, target.digest), true);
  assert.equal(store.acceptedEvents()[0].record.payload.count, 4);
  // 冲突已处理完毕
  assert.equal(store.resolveConflict("e1", ConflictResolution.KEEP_EXISTING), false);
});

test("并发接收：相同内容只接受一次", async () => {
  const store = createEventStore();
  const tasks = [];
  for (let i = 0; i < 50; i += 1) tasks.push(store.ingestOne(makeEvent()));
  const results = await Promise.all(tasks);
  assert.equal(results.filter((r) => r.status === IngestStatus.ACCEPTED).length, 1);
  assert.equal(results.filter((r) => r.status === IngestStatus.DUPLICATE).length, 49);
  assert.equal(store.size, 1);
  assert.equal(store.pendingConflicts().length, 0);
});

test("并发接收：同标识不同内容只接受一次，其余全部登记冲突", async () => {
  const store = createEventStore();
  const tasks = [];
  for (let i = 0; i < 50; i += 1) {
    tasks.push(store.ingestOne(makeEvent({ payload: { count: i } })));
  }
  const results = await Promise.all(tasks);
  assert.equal(results.filter((r) => r.status === IngestStatus.ACCEPTED).length, 1);
  assert.equal(results.filter((r) => r.status === IngestStatus.CONFLICT).length, 49);
  assert.equal(store.size, 1);
  const conflicts = store.pendingConflicts();
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].incoming.length, 49);
});

test("并发混合批次：统计一致且序号绑定不乱", async () => {
  const store = createEventStore();
  const tasks = [];
  for (let i = 0; i < 10; i += 1) {
    tasks.push(
      store.ingestBatch([
        makeEvent({ event_id: `ok-${i}` }),
        null,
        makeEvent({ event_id: `ok-${i}` }),
      ]),
    );
  }
  const results = await Promise.all(tasks);
  for (const batch of results) {
    assert.deepEqual(
      batch.map((r) => r.index),
      [0, 1, 2],
    );
    assert.deepEqual(
      batch.map((r) => r.status),
      [IngestStatus.ACCEPTED, IngestStatus.REJECTED, IngestStatus.DUPLICATE],
    );
  }
  assert.equal(store.size, 10);
});

test("输出不回显原型上的敏感值", async () => {
  const secret = "proto-leaked-token";
  Object.prototype.credential = secret;
  try {
    const store = createEventStore();
    const record = makeEvent({ event_id: "evt-clean" });
    const result = await store.ingestOne(record);
    assert.equal(result.status, IngestStatus.ACCEPTED);
    const outputs =
      JSON.stringify(result) +
      JSON.stringify(store.acceptedEvents()) +
      JSON.stringify(store.pendingConflicts()) +
      safeJsonStringify(record);
    assert.ok(!outputs.includes(secret));
    assert.ok(!outputs.includes("credential"));
    assert.ok(!Object.hasOwn(store.acceptedEvents()[0].record, "credential"));
  } finally {
    delete Object.prototype.credential;
  }
});

test("错误结果只含问题代码，不回显记录内容", async () => {
  const store = createEventStore();
  const record = makeEvent({ event_id: "evt-secret" });
  record.payload.note = "do-not-echo";
  delete record.kind;
  const result = await store.ingestOne(record);
  assert.equal(result.status, IngestStatus.REJECTED);
  assert.deepEqual(result.problems, [{ code: "MISSING_FIELD", field: "kind" }]);
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes("do-not-echo"));
  assert.ok(!serialized.includes("evt-secret"));
});

test("正常医疗资源事件的校验与接收输出保持不变", async () => {
  const sample = JSON.parse(await readFile(new URL("../data/sample.json", import.meta.url), "utf8"));

  // 旧契约：合法样例返回空数组
  assert.deepEqual(validateEvent(sample), []);
  // 每种既有事件名称都保持兼容
  for (const kind of EVENT_KINDS) {
    assert.deepEqual(validateEvent({ ...sample, kind }), []);
  }

  // 接收输出确定：两个独立存储给出相同摘要与相同事件标识
  const a = createEventStore();
  const b = createEventStore();
  const ra = await a.ingestOne(sample);
  const rb = await b.ingestOne(sample);
  assert.equal(ra.status, IngestStatus.ACCEPTED);
  assert.equal(rb.status, IngestStatus.ACCEPTED);
  assert.equal(ra.digest, rb.digest);
  assert.equal(ra.eventId, sample.event_id);

  // 存储内容与原样例逐字段一致，重放判为重复
  assert.deepEqual(a.acceptedEvents()[0].record, sample);
  const again = await a.ingestOne(sample);
  assert.equal(again.status, IngestStatus.DUPLICATE);
});
