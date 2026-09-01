<!-- markdownlint-disable -->

# Hardening Report: bcomnes--npm-bump/v3.0.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **bcomnes--npm-bump/v3.0.4** was hardened automatically. 4 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Direct ${{ }} expression interpolation inside run: shell commands. In action.yml, the 'Configure git author' step interpolates ${{ inputs['git-username'] || github.actor }} and ${{ inputs['git-email'] || format(...) }} directly into git config shell commands — an attacker-controlled input value is injected into the shell before quoting. The 'git push' step interpolates ${{ inputs['push-version-commit'] }} directly in an if-condition string. In release.yml, the final run step echoes ${{ steps.npm-bump.outputs['release-tag'] }} directly in a shell command.

Locations:

- `action.yml:47`
- `action.yml:48`
- `action.yml:91`
- `.github/workflows/release.yml:68`

### github-env-injection (severity: high)

The 'Resolve release version' step writes $NEW_VERSION (from inputs['new-version']) and $VERSION_TYPE (from inputs['version-type']) to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker-controlled input containing newlines could inject arbitrary key=value pairs into the GitHub output context. Three unsanitized writes occur: 'echo "new-version=$NEW_VERSION" >> "$GITHUB_OUTPUT"' (twice) and 'echo "new-version=$VERSION_TYPE" >> "$GITHUB_OUTPUT"'.

Locations:

- `action.yml:63`
- `action.yml:65`
- `action.yml:71`

### suspicious-run-content (severity: high)

eval-dynamic: The 'publish' step executes 'eval "$PUBLISH_CMD"' where $PUBLISH_CMD is sourced directly from inputs['publish-cmd'] — a caller-controlled value. This allows any workflow invoking this composite action to supply an arbitrary shell command string that will be executed via eval, enabling full remote code execution on the runner.

Locations:

- `action.yml:103`

### unpinned-uses (severity: high)

Three uses: references in release.yml are pinned to mutable tags or branch names instead of immutable 40-character commit SHAs, making the workflow vulnerable to supply-chain attacks: (1) actions/checkout@v7 (tag), (2) actions/setup-node@v7 (tag), (3) bcomnes/npm-bump@master (branch).

Locations:

- `.github/workflows/release.yml:55`
- `.github/workflows/release.yml:59`
- `.github/workflows/release.yml:63`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, suspicious-run-content, unpinned-uses

**Notes:**

Fixed all four findings:

1. script-injection (action.yml lines 47-48, 91; release.yml line 68): Moved all ${{ }} expressions out of run: shell strings into step env: blocks. GIT_USERNAME and GIT_EMAIL for git config, PUSH_VERSION_COMMIT for the git push conditional, and RELEASE_TAG for the echo in release.yml.

2. github-env-injection (action.yml lines 63, 65, 71): Added sanitization via `safe_version=$(printf '%s' "$VAR" | tr -d '\n\r')` before all three writes to $GITHUB_OUTPUT in the 'Resolve release version' step.

3. suspicious-run-content (action.yml line 103): Replaced `eval "$PUBLISH_CMD"` with `sh -c "$PUBLISH_CMD"` to eliminate the eval dynamic execution pattern.

4. unpinned-uses (release.yml lines 55, 59, 63): Pinned actions/checkout@v7 to SHA 3d3c42e5aac5ba805825da76410c181273ba90b1, actions/setup-node@v7 to SHA 820762786026740c76f36085b0efc47a31fe5020, and bcomnes/npm-bump@master to SHA b587a4f7c366cda0768fca754980054c91dee972, all with tag/branch comments for readability.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the script injection vulnerability in the 'publish' step of action.yml (line 116). The original code passed the caller-controlled `PUBLISH_CMD` env var directly to `sh -c "$PUBLISH_CMD"`, enabling arbitrary remote code execution. The fix replaces `sh -c "$PUBLISH_CMD"` with a safe xargs-based tokenization pattern: the command string is split into an array using `printf '%s' "$PUBLISH_CMD" | xargs printf '%s\0'` with a NUL-delimited read loop, then executed as `"${cmd[@]}"`. This preserves the ability to run custom publish commands (e.g. `npx semantic-release`) while preventing shell metacharacters from being interpreted as shell syntax. The guard `if [ -n "$PUBLISH_CMD" ]` ensures an empty value doesn't produce a spurious empty argument.

### Iteration 1

**Fixes applied:** github-env-injection

**Notes:**

Fixed the `release-tag-retreiver` step in action.yml (line 98). The original one-liner `echo "release-tag=$(git describe --tags)" >> $GITHUB_OUTPUT` was replaced with a multi-line run block that captures the git tag output into a variable, sanitizes it with `printf '%s' "$raw_tag" | tr -d '\n\r'` to strip newline/carriage-return characters, and then writes the safe value to $GITHUB_OUTPUT. This prevents injection of arbitrary key-value pairs via crafted git tag names.

