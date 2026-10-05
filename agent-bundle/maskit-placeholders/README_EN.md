# Maskit placeholder Skill (agent-bundle)

A **behavior contract** for coding assistants: when you see a Maskit placeholder, use it
verbatim — do not invent tokens, do not substitute sample data, do not refuse without
cause, and do not claim an unfinished task succeeded.

Maskit is a local man-in-the-middle gateway; it cannot see or change how a host
(Claude Code / Cursor / Codex CLI / Qoder, ...) assembles its system prompt. The contract
therefore has to be installed through the host's own mechanism (Skill / rules /
AGENTS.md). This directory is its single source of truth.

```
agent-bundle/maskit-placeholders/
├── contract.md                   # Source of truth: the 12 rules (rule text lives here)
├── SKILL.md                      # Render target: Agent Skills hosts (Claude Code, ...)
├── templates/AGENTS.snippet.md   # Render target: AGENTS.md / rules snippet
├── README.md / README_EN.md      # This file: installation and limits
└── (rendered by `scripts/pack-skill.py --render`; do not edit generated files)
```

## Where to get it

- **Release asset**: `Maskit_<version>_skill.zip` (same Release as installers/extension);
- **Local panel**: "Download skill package" in Settings (`GET /api/skill/bundle`, works for
  desktop installs and container deployments);
- **Repository**: use this directory directly.

## Install (per host mechanism, **not individually verified**)

> ⚠️ The table below lists **candidate mechanisms**; Maskit has not verified each host's
> current behavior. Hosts iterate quickly and paths may change. Check the host's official
> documentation before installing, and confirm the skill is actually loaded (see
> "Confirming it is loaded"). Do not treat "the file exists on disk" as "loaded at runtime".

| Host | Mechanism | Where |
|---|---|---|
| Claude Code | Agent Skills (`SKILL.md` + YAML frontmatter) | `~/.claude/skills/maskit-placeholders/` or project `.claude/skills/maskit-placeholders/` |
| Qoder | Skill directory (plus a marketplace channel) | user resource dir / project dir |
| Cursor | rules (`.mdc`, frontmatter `description` / `globs` / `alwaysApply`) | project `.cursor/rules/`, body from `templates/AGENTS.snippet.md` |
| Codex CLI | `AGENTS.md` | project root `AGENTS.md`, or `~/.codex/AGENTS.md` |
| Gemini CLI | `GEMINI.md` | project root `GEMINI.md` |
| Others | no fixed mechanism | copy `templates/AGENTS.snippet.md` into whatever file the client reads |

Note: the contract body is written in Chinese. Keep it as-is so that the rule text stays
byte-identical to the rendered targets; translate only if you are prepared to maintain a
separate contract.

## Confirming it is loaded

Hosts surface skill status differently (slash command, `/skills` list, startup banner).
If unsure, observe behavior: does the model keep placeholder tokens verbatim, and stop
suggesting "turn masking off" or asking for raw values? **Absence of errors is not
evidence that the skill loaded.**

## Cache impact

- The host preloads only `name` + `description` (a few dozen tokens). The first request
  after installation misses the prompt cache once, then stabilizes.
- The body loads on trigger and is appended near the end of the conversation; it does not
  move the prefix.
- Maskit does not modify any request's system prompt by default: injected instructions
  would have to be byte-constant and must not break client-set `cache_control` breakpoints,
  which costs more than it buys.

## Limits (honest statement)

- This contract does **not** guarantee that a model never hallucinates, rewrites tokens, or
  refuses; passing static document tests is not the same as model compliance.
- It exposes no API to read the original mapping and does not replace user authorization:
  network calls, deletions and releases still require the user's consent.
- Restoration only happens on supported paths and depends on the mapping being available;
  cross-session/restart behavior follows the engine's restoration contract.
