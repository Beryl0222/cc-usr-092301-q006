// 群众赛事医疗调度 —— 事件接收流程。
//
// 职责：
//   * 批量接收记录，每条结果与原序号绑定；
//   * 单条记录的读取异常只隔离该条，不影响同批其他记录；
//   * 通过校验的记录按 事件标识(event_id) + 规范化摘要(全内容 sha256) 去重；
//   * 同一标识但内容不同的重放登记为“待人工处理”的冲突 —— 既不静默采用
//     先到版本，也不静默采用后到版本；
//   * 并发接收时提交阶段串行化，去重/冲突判定不存在检查-写入竞态；
//   * 所有输出（结果、冲突、已接收事件）只含自身数据属性的净化副本，
//     原型上的敏感值不会进入日志或错误响应。

import {
  Problem,
  canonicalDigest,
  canonicalJson,
  readOwnDataValue,
  validateEventDetailed,
} from "./race_medical_dispatch.js";

export const IngestStatus = Object.freeze({
  ACCEPTED: "ACCEPTED",
  DUPLICATE: "DUPLICATE",
  CONFLICT: "CONFLICT",
  REJECTED: "REJECTED",
});

export const ConflictResolution = Object.freeze({
  KEEP_EXISTING: "KEEP_EXISTING",
  ACCEPT_INCOMING: "ACCEPT_INCOMING",
});

// 极简互斥锁：校验可并行，写库必须排队，避免并发下的检查-写入竞态。
function createMutex() {
  let tail = Promise.resolve();
  return (fn) => {
    const run = tail.then(fn);
    tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  };
}

// 结果中展示用的事件标识：字符串直接用，其他 JSON 类型用规范化文本。
// 只来自记录自身的数据属性，绝不读原型。
function displayId(idValue) {
  return typeof idValue === "string" ? idValue : canonicalJson(idValue);
}

export function createEventStore() {
  const accepted = new Map(); // eventKey -> { eventKey, digest, canonical }
  const conflicts = new Map(); // eventKey -> { eventKey, eventId, existingDigest, existingCanonical, incoming: Map<digest, canonical> }
  const serialize = createMutex();

  function validateOne(record, index) {
    try {
      return { index, record, detail: validateEventDetailed(record) };
    } catch {
      // 校验器按契约不抛错；这是兜底，确保任何意外异常只隔离该条。
      return {
        index,
        record,
        detail: { valid: false, problems: [{ code: Problem.UNREADABLE_RECORD }] },
      };
    }
  }

  // 仅处理“已通过校验”的记录：此时 event_id 是自身数据属性，
  // 规范化读取不会触发任何外来代码。
  function commitOne(verdict) {
    const { index, record } = verdict;
    const idValue = readOwnDataValue(record, "event_id");
    const eventKey = canonicalJson(idValue);
    const digest = canonicalDigest(record);
    const canonical = canonicalJson(record);
    const eventId = displayId(idValue);

    const existing = accepted.get(eventKey);
    if (!existing) {
      accepted.set(eventKey, { eventKey, digest, canonical });
      return { index, status: IngestStatus.ACCEPTED, eventId, digest };
    }
    if (existing.digest === digest) {
      return { index, status: IngestStatus.DUPLICATE, eventId, digest };
    }

    // 同一标识、不同内容：登记冲突待人工处理，不改动已接收版本。
    let conflict = conflicts.get(eventKey);
    if (!conflict) {
      conflict = {
        eventKey,
        eventId,
        existingDigest: existing.digest,
        existingCanonical: existing.canonical,
        incoming: new Map(),
      };
      conflicts.set(eventKey, conflict);
    }
    conflict.incoming.set(digest, canonical); // 相同内容的重放只登记一次
    return { index, status: IngestStatus.CONFLICT, eventId, digest, existingDigest: existing.digest };
  }

  /**
   * 接收一组记录。返回与输入等长的结果数组，每个结果带原序号 index。
   * @param {Array} records
   */
  async function ingestBatch(records) {
    if (!Array.isArray(records)) {
      throw new TypeError("ingestBatch 需要记录数组");
    }
    // Array.from 会访问稀疏数组的空洞（得到 undefined），保证每个序号都有结果。
    const verdicts = Array.from(records, (record, index) => validateOne(record, index));
    return serialize(() =>
      verdicts.map((verdict) => {
        if (!verdict.detail.valid) {
          return {
            index: verdict.index,
            status: IngestStatus.REJECTED,
            problems: verdict.detail.problems,
          };
        }
        return commitOne(verdict);
      }),
    );
  }

  async function ingestOne(record) {
    const [result] = await ingestBatch([record]);
    return result;
  }

  /** 已接收事件的净化视图（规范化副本，与调用方对象脱钩）。 */
  function acceptedEvents() {
    return [...accepted.values()].map((entry) => ({
      eventId: displayId(JSON.parse(entry.eventKey)),
      digest: entry.digest,
      record: JSON.parse(entry.canonical),
    }));
  }

  /** 待人工处理的冲突队列（净化副本）。 */
  function pendingConflicts() {
    return [...conflicts.values()].map((conflict) => ({
      eventId: conflict.eventId,
      existingDigest: conflict.existingDigest,
      existing: JSON.parse(conflict.existingCanonical),
      incoming: [...conflict.incoming.entries()].map(([digest, canonical]) => ({
        digest,
        record: JSON.parse(canonical),
      })),
    }));
  }

  /**
   * 人工处理冲突。
   * @param {*} eventIdValue 事件标识（与记录中的 event_id 同值）
   * @param {string} resolution ConflictResolution 之一
   * @param {string} [incomingDigest] ACCEPT_INCOMING 且存在多个版本时必传
   * @returns {boolean} 是否存在该冲突
   */
  function resolveConflict(eventIdValue, resolution, incomingDigest) {
    const eventKey = canonicalJson(eventIdValue);
    const conflict = conflicts.get(eventKey);
    if (!conflict) return false;

    if (resolution === ConflictResolution.ACCEPT_INCOMING) {
      let digest = incomingDigest;
      if (digest === undefined) {
        if (conflict.incoming.size !== 1) {
          throw new TypeError("存在多个冲突版本，必须指定 incomingDigest");
        }
        [digest] = conflict.incoming.keys();
      }
      const canonical = conflict.incoming.get(digest);
      if (canonical === undefined) {
        throw new TypeError(`未知的 incomingDigest: ${digest}`);
      }
      accepted.set(eventKey, { eventKey, digest, canonical });
    } else if (resolution !== ConflictResolution.KEEP_EXISTING) {
      throw new TypeError(`未知的处理方式: ${resolution}`);
    }

    conflicts.delete(eventKey);
    return true;
  }

  return {
    ingestBatch,
    ingestOne,
    acceptedEvents,
    pendingConflicts,
    resolveConflict,
    get size() {
      return accepted.size;
    },
  };
}
