<!-- markdownlint-disable -->

# Hardening Report: bcomnes--npm-bump/v3.0.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **bcomnes--npm-bump/v3.0.4** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Configure git author' step directly interpolates ${{ inputs['git-username'] || github.actor }} and ${{ inputs['git-email'] || format('{0}@users.noreply.github.com', github.actor) }} inside a run: shell string. Attacker-controlled input values are template-substituted into the shell command before execution, enabling command injection via crafted git-username or git-email inputs.

Locations:

- `action.yml:46`

### script-injection (severity: high)

Sub-rule (a): The 'git push' step directly interpolates ${{ inputs['push-version-commit'] }} inside a run: shell string (used in an `if` condition). Any ${{ }} expression inside a run: block is a script-injection risk regardless of how it is used.

Locations:

- `action.yml:79`

### github-env-injection (severity: high)

The 'Resolve release version' step writes $NEW_VERSION and $VERSION_TYPE (sourced from inputs['new-version'] and inputs['version-type'] respectively) to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker can inject newlines to poison GITHUB_OUTPUT and set arbitrary output variables.

Locations:

- `action.yml:57`

### suspicious-run-content (severity: high)

eval-dynamic: The 'publish' step executes `eval "$PUBLISH_CMD"` where PUBLISH_CMD is set from inputs['publish-cmd'] — a fully attacker-controlled value. This allows any caller of the action to execute arbitrary shell commands on the runner by supplying a malicious publish-cmd input.

Locations:

- `action.yml:93`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, suspicious-run-content

**Notes:**

Fixed all four findings in action.yml:
1. 'Configure git author' step: moved ${{ inputs['git-username'] || github.actor }} and ${{ inputs['git-email'] || format(...) }} into env: block as GIT_USERNAME and GIT_EMAIL, referenced via shell variables.
2. 'Resolve release version' step: sanitized NEW_VERSION and VERSION_TYPE before writing to $GITHUB_OUTPUT using printf '%s' "$VAR" | tr -d '\n\r', with two-step capture to preserve exit status under set -euo pipefail.
3. 'git push' step: moved ${{ inputs['push-version-commit'] }} into env: block as PUSH_VERSION_COMMIT, referenced via shell variable.
4. 'publish' step: replaced eval "$PUBLISH_CMD" with writing the command to a mktemp file and executing it with bash -eo pipefail, preserving errexit/pipefail behavior matching the step's shell: bash context.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script-injection in the 'publish' step of action.yml. The original code wrote PUBLISH_CMD (from inputs['publish-cmd']) to a temp file and executed it with `bash -eo pipefail`, allowing arbitrary shell code execution. Replaced with xargs-based tokenization: `printf '%s' "$PUBLISH_CMD" | xargs printf '%s\0'` with a null-delimited while/read loop builds an array of tokens, then `"${_cmd_args[@]}"` executes the command with proper argument boundaries. This prevents shell metacharacter injection while preserving the ability to specify a custom publish command with arguments. The ${{ }} expression remains in the env: block.

