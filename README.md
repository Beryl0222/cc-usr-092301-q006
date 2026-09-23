# 群众赛事医疗资源编排

本项目用于整理群众赛事医疗资源编排领域中的事件名称、交换字段与脱敏样例，方便业务、运营和研发人员在同一套术语下讨论后续服务。资料只包含领域约定，不包含真实个人信息、生产连接或外部账号。

## 目录

- `src/race_medical_dispatch.js`：事件种类、合同校验与安全序列化。
- `src/event_store.js`：批量接收、去重与重放冲突处理。
- `data/sample.json`：用于核对资料格式的虚构事件。
- `tests/`：合同兼容、安全边界与接收流程的测试。

## 合同校验

`validateEvent(record)` 保持旧契约：合法记录返回 `[]`，非法记录返回问题标识数组（缺失字段仍按字段名报告，未知事件种类报告 `"kind"`）。`validateEventDetailed(record)` 返回结构化的 `{ valid, problems }`，问题代码见 `Problem`。

校验只接受普通 JSON 对象**自身拥有**的字段，绝不沿原型链查找（不再使用 `in`），且全程只读属性描述符，不会执行记录或其原型链上的任何外来代码（getter / Proxy 陷阱）。对下列情况给出确定错误而不是抛异常：

| 情况 | 问题代码 |
| --- | --- |
| 空记录（null / undefined） | `EMPTY_RECORD` |
| 非对象（数字、字符串等） | `NOT_AN_OBJECT` |
| 顶层是数组 | `ARRAY_REJECTED` |
| 原型被替换 / 类实例 | `PROTOTYPE_POLLUTED` |
| 危险键 `__proto__` / `constructor` / `prototype` | `DANGEROUS_KEY` |
| 访问器属性（getter/setter） | `ACCESSOR_PROPERTY` |
| 循环结构 | `CIRCULAR_STRUCTURE` |
| 非 JSON 值（函数、Symbol、BigInt、NaN 等） | `NON_JSON_VALUE` |
| 必填字段缺失（含仅存在于原型链上） | `MISSING_FIELD` |
| 未知事件种类 | `UNKNOWN_KIND` |
| 读取异常（如已撤销的 Proxy） | `UNREADABLE_RECORD` |

## 接收流程

`createEventStore()` 提供事件接收存储：

- `ingestBatch(records)` / `ingestOne(record)`：逐条校验，结果与原序号绑定；单条读取异常只隔离该条，不影响同批其他记录。
- 通过校验的记录按 **事件标识 + 规范化摘要**（键排序 JSON 的 sha256）去重：同标识同内容为 `DUPLICATE`（幂等重放）。
- 同标识但内容不同的重放标记为 `CONFLICT`，进入 `pendingConflicts()` 等待人工处理 —— 不静默采用先到或后到版本；用 `resolveConflict(eventId, resolution, digest?)` 显式处理。
- 并发接收时提交阶段串行化，去重/冲突判定无竞态。
- 所有输出（结果、冲突、已接收事件、日志序列化）只含自身数据属性的净化副本，原型上的敏感值不会被回显；`safeJsonStringify` 供日志与错误响应使用。

## 本地核对

```bash
npm test
```
