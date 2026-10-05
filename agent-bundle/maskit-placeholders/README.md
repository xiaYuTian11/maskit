# Maskit 占位符 Skill（agent-bundle）

给编程助手用的一份**行为契约**：看到 Maskit 占位符时，原样使用、不编造、不替换成
模拟数据、不无谓拒绝，也不把未完成的任务说成完成。

Maskit 是本地中间人网关，它**看不到也改不了**宿主（Claude Code / Cursor / Codex CLI
/ Qoder 等）如何组装系统提示，所以这份契约只能以宿主自己的机制安装（Skill / rules
/ AGENTS.md）。本目录是它的唯一真相源。

```
agent-bundle/maskit-placeholders/
├── contract.md                   # 真相源：12 条规则的正文（改规则只改这里）
├── SKILL.md                      # 渲染目标：Agent Skills 宿主（Claude Code 等）
├── templates/AGENTS.snippet.md   # 渲染目标：AGENTS.md / rules 片段（其它宿主）
├── README.md / README_EN.md      # 本文件：安装方式与边界
└── （渲染由 `scripts/pack-skill.py --render` 完成，勿手改生成物）
```

## 获取

- **Release 资产**：`Maskit_<版本>_skill.zip`（与安装包、扩展包同一 Release）；
- **本地面板**：设置页「下载 Skill 包」（`GET /api/skill/bundle`，桌面端与容器部署都可用）；
- **仓库**：直接使用本目录。

## 安装（按宿主机制，**未逐个实测**）

> ⚠️ 下表是各宿主的**候选机制**，Maskit 没有逐个实测过版本行为：宿主迭代很快，
> 目录与文件名可能变化。安装前请以宿主官方文档为准；装完确认它确实被加载
> （见下面「怎么确认装上了」），不要把"目录里有文件"当成"运行时已加载"。

| 宿主 | 机制 | 放哪里 |
|---|---|---|
| Claude Code | Agent Skills（`SKILL.md` + YAML frontmatter） | 用户级 `~/.claude/skills/maskit-placeholders/`，或项目级 `.claude/skills/maskit-placeholders/` |
| Qoder | Skill 目录（另有扩展市场通道） | 用户资源目录 / 项目目录 |
| Cursor | rules（`.mdc`，frontmatter 形如 `description` / `globs` / `alwaysApply`） | 项目 `.cursor/rules/`，正文用 `templates/AGENTS.snippet.md` |
| Codex CLI | `AGENTS.md` | 项目根 `AGENTS.md`，或用户级 `~/.codex/AGENTS.md` |
| Gemini CLI | `GEMINI.md` | 项目根 `GEMINI.md` |
| 其它 | 无固定机制 | 复制 `templates/AGENTS.snippet.md` 的内容到该客户端能读到的说明文件 |

`SKILL.md` 的 frontmatter 里 `description` 写明了触发条件——宿主只预加载 `name` +
`description`，正文按需读取，所以**不要把 description 删掉或改短**。

### 怎么确认装上了

不同宿主显示加载状态的入口不同（同名命令、`/skills` 列表、启动时的技能清单等）。
在没有把握时，可以观察行为：模型遇到占位符后是否原样保留 token、是否不再建议
"关闭脱敏"或索要原文。**不要把"我没看到它报错"当成"已加载"。**

## 与缓存的关系（回答"影响缓存吗"）

- 宿主启动只把 `name` + `description`（几十 token）放进系统提示；安装后**第一个
  请求**必然缓存 miss 一次，随后重新稳定。
- 正文只在触发时加载，追加在会话尾部，不改变历史前缀。
- Maskit 默认**不改任何请求的系统提示**：注入式说明（把契约塞进每条请求）需要字节
  恒定地注入、且不破坏客户端已设的 `cache_control` 断点，风险高于收益。

## 边界（诚实声明）

- 本契约**不承诺**杜绝模型幻觉、改写或拒答；静态文档测试通过 ≠ 模型一定遵守。
- 契约不提供读取原文映射的接口，也不能替代用户授权：涉及网络请求、删除、发布的
  动作仍以用户授权为准。
- 还原只在受支持的链路上生效，且依赖当时的映射是否可用；跨会话/重启后的行为以
  引擎的还原契约为准。
