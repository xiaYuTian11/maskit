# 分支保护配置（master）

在 GitHub 仓库 **Settings → Branches → Add branch ruleset**（或 classic branch protection）对 `master` 启用以下规则。job 名与 `.github/workflows/ci.yml` 中的 `jobs.<id>.name` 一一对应。

## 必选

| 规则 | 值 | 目的 |
|------|----|------|
| Require a pull request before merging | 开 | 禁止直接 push master |
| Required approvals | 1 | 至少维护者审阅一次（CODEOWNERS 自动请求） |
| Dismiss stale approvals when new commits are pushed | 开 | 审阅后又推代码要重审 |
| Require review from Code Owners | 开 | `.github/CODEOWNERS` |
| Require status checks to pass before merging | 开 | 下面五个 check 必须全绿 |
| Required status checks | `python`、`frontend`、`rust`、`rust-macos`、`version` | 分别对应单测+冒烟、前端构建/Lint/i18n/env 解析、Rust 编译+单测（Windows）、Rust 编译+单测（macOS）、版本号一致 |
| Require branches to be up to date before merging | 开 | 避免合并旧基线 |
| Require conversation resolution before merging | 开 | 评论没处理完不能合 |
| Block force pushes | 开 | 保护历史 |
| Do not allow deletions | 开 | |

## 建议

| 规则 | 说明 |
|------|------|
| Require linear history | 配合「Squash and merge」保持主干一条线 |
| Require signed commits | 可选；开启后贡献者需配置 GPG/SSH 签名 |
| Allowed merge methods | 仅 Squash（PR 标题即最终 commit，需符合 Conventional Commits） |

## 仓库其它设置

- **Settings → General → Features**：开启 Discussions（issue 模板里的「使用交流」链接指向它）；开启 Security → Private vulnerability reporting。
- **Settings → Code security**：开启 Dependabot alerts / security updates（`.github/dependabot.yml` 已配置版本更新）、Secret scanning + Push protection。
- **Settings → Actions → General**：Workflow permissions 选 *Read repository contents*（工作流内部已按 job 声明写权限）；Fork PR 需要维护者批准后才运行 Actions。
- **Settings → Secrets and variables → Actions**：Release 工作流构建多平台安装包与 Docker 镜像。Windows 与 macOS 安装包均由 GitHub Actions `desktop` 矩阵自动编译打包并上传到 Release 草稿；若配置了 `TAURI_SIGNING_PRIVATE_KEY` 会自动生成签名，未配置时作为未签名资产上传。

## 首次推送后的校验

1. 开一个只改文档的 PR，确认**五个** check 都出现且为必需。
2. 尝试直接 `git push origin master`，应被拒绝。

> `rust-macos` 是 0.2.8 新增的 job（macOS 侧编译 + 单测）。它**不会自动成为必需项**：
> GitHub 只在 check 至少跑过一次之后才允许把它加进 Required status checks，因此要
> 先让一个 PR 触发它跑完，再回到 ruleset 里勾上。漏勾的后果是它只跑不拦 ——
> macOS 分支的编译错误仍可能合进 master。
>
> 用 CLI 核对当前必需项（避免只靠记忆）：
>
> ```bash
> gh api repos/{owner}/{repo}/branches/master/protection \
>   --jq '.required_status_checks.contexts'
> ```
>
> 返回里应包含上表五个名字。ruleset（新版分支保护）改用
> `gh api repos/{owner}/{repo}/rulesets` 查看。
