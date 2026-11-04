/**
 * 凭据类标签的**唯一定义源**（前端侧）。
 *
 * 为什么这是硬约束而不是「建议」：词库的分类名会原样成为占位符的 label，
 * 引擎按 `label in CREDENTIAL_LABELS` 决定事件库写不写原文 —— 非凭据类写
 * `items[].original` 明文，凭据类只写 digest + preview。把密钥导进一个不在
 * 这个集合里的分类（例如 `PASSWORD` / `APP_SECRET`），等于把密钥明文写进本地
 * SQLite，与「凭据永不落库」的红线直接冲突。
 *
 * 同时它也是**展示侧**的红线：Stats 排行榜 / Dashboard 明细的「显示明文」开关
 * 只对非凭据词生效，凭据词永远打码。以前这里与 `env-import.ts` 各写一份、
 * 都少 CONNSTR 与 PRIVATE_KEY，导致这两类词可以被明文展示。
 *
 * 引擎侧对应 `engine/credential_labels.py`，两侧由
 * `tests/test_regressions.py::test_credential_label_sets_stay_in_sync` 守死不漂移。
 */
export const CREDENTIAL_LABELS = [
  'API_KEY',
  'TOKEN',
  'SECRET',
  'ACCESS_KEY',
  'JWT',
  'CONNSTR',
  'PRIVATE_KEY',
] as const

export type CredentialLabel = (typeof CREDENTIAL_LABELS)[number]

/** 便于 `Set` 场景的查表用法（`.has(label)`）。 */
export const CRED_LABELS: ReadonlySet<string> = new Set(CREDENTIAL_LABELS)

/**
 * 展示侧判定：该标签是否必须恒打码。
 *
 * `extra` 是配置里的 `credential_categories`（用户显式标记的自定义分类，
 * 如「密钥」）。两半条件必须合并判断——只看内置集合会让中文分类里的
 * 密钥在「显示明文」开关下被展开（引擎侧已不落原文，但展示层不能靠落库形态
 * 反推：早期版本的同一条历史事件里可能就躺着原文）。
 */
export function isCredentialLabel(label: string, extra?: readonly string[]): boolean {
  if (CRED_LABELS.has(label)) return true
  return Array.isArray(extra) && extra.includes(label)
}
