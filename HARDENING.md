<!-- markdownlint-disable -->

# Hardening Report: bcomnes--npm-bump/v2.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **bcomnes--npm-bump/v2.2.0** was hardened automatically. 6 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `run:` steps in action.yml directly interpolate `${{ inputs.* }}` expressions into shell commands (rule a), allowing an attacker-controlled caller to inject arbitrary shell commands.

1. Line 37: `run: git config --global user.email "${{ inputs.git_email }}"` — inputs.git_email interpolated directly.
2. Line 39: `run: git config --global user.name "${{ inputs.git_username }}"` — inputs.git_username interpolated directly.
3. Line 41: `run: npm version ${{ inputs.newversion }}` — inputs.newversion interpolated directly AND unquoted (also rule b).
4. Line 49: `if [ "${{ inputs.push_version_commit }}" = "true" ]` — inputs.push_version_commit interpolated directly inside a run block.
5. Line 55: `run: ${{ inputs.publish_cmd }}` — the entire shell command is an attacker-controlled input expression; this is the most critical instance as it allows arbitrary command execution.

Locations:

- `action.yml:37`
- `action.yml:39`
- `action.yml:41`
- `action.yml:49`
- `action.yml:55`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git_email }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:38`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.git_username }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:40`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.newversion }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:42`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.push_version_commit }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:49`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.publish_cmd }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:56`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection

**Notes:**

Fixed all 5 script injection instances in action.yml by moving ${{ inputs.* }} expressions into env: blocks:
1. inputs.git_email → GIT_EMAIL env var in git config step
2. inputs.git_username → GIT_USERNAME env var in git config step
3. inputs.newversion → NEWVERSION env var in npm version step (also properly quoted)
4. inputs.push_version_commit → PUSH_VERSION_COMMIT env var in conditional push step
5. inputs.publish_cmd → PUBLISH_CMD env var, executed via bash -c to preserve the action's intended behavior of running an arbitrary command

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection at action.yml line 62: replaced `bash -c "$PUBLISH_CMD"` with a safe array-based execution pattern using `read -ra cmd <<< "$PUBLISH_CMD"` followed by `"${cmd[@]}"`. This prevents shell metacharacters (`;`, `|`, `&`, `$(...)`, etc.) in the caller-controlled `publish_cmd` input from being interpreted as shell syntax, while still allowing the command to be specified as a space-separated string (e.g., `npm publish`).

