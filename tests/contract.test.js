import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { EVENT_KINDS, validateEvent } from "../src/race_medical_dispatch.js";

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

test("样例符合领域约定", async () => {
  const record = JSON.parse(await readFile(new URL("../data/sample.json", import.meta.url), "utf8"));
  assert.deepEqual(validateEvent(record), []);
});

test("所有既有事件名称保持兼容", () => {
  for (const kind of EVENT_KINDS) {
    assert.deepEqual(validateEvent(makeEvent({ kind })), []);
  }
});

test("缺失必填字段仍按字段名报告", () => {
  const problems = validateEvent({});
  assert.deepEqual(
    [...problems].sort(),
    ["event_id", "kind", "occurred_at", "payload", "subject_id"].sort(),
  );
});

test("未知事件种类报告 kind", () => {
  assert.deepEqual(validateEvent(makeEvent({ kind: "BOGUS_KIND" })), ["kind"]);
});

test("空值与非对象返回确定错误而不是终止", () => {
  // 生产故障一：空记录曾让校验函数直接抛错终止。
  assert.deepEqual(validateEvent(null), ["EMPTY_RECORD"]);
  assert.deepEqual(validateEvent(undefined), ["EMPTY_RECORD"]);
  assert.deepEqual(validateEvent(42), ["NOT_AN_OBJECT"]);
  assert.deepEqual(validateEvent("evt"), ["NOT_AN_OBJECT"]);
  assert.deepEqual(validateEvent(true), ["NOT_AN_OBJECT"]);
  assert.deepEqual(validateEvent([]), ["ARRAY_REJECTED"]);
  assert.deepEqual(validateEvent([makeEvent()]), ["ARRAY_REJECTED"]);
});
