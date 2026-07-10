<!-- markdownlint-disable -->

# Hardening Report: bcomnes--npm-bump/v3.0.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **bcomnes--npm-bump/v3.0.2** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Direct ${{ }} expression interpolation inside run: shell commands in action.yml. (1) Line 41: `git config --global user.name "${{ inputs['git-username'] || github.actor }}"` — attacker-controlled inputs interpolated directly into shell. (2) Line 42: `git config --global user.email "${{ inputs['git-email'] || format(...) }}"` — same issue. (3) Line 76: `if [ "${{ inputs['push-version-commit'] }}" = "true" ]` — input interpolated directly into a shell conditional. (4) Line 81: `run: ${{ inputs['publish-cmd'] }}` — the entire run command is an attacker-controlled input, allowing arbitrary command execution.

Locations:

- `action.yml:41`
- `action.yml:42`
- `action.yml:76`
- `action.yml:81`

### script-injection (severity: high)

Rule (a): Direct ${{ }} expression interpolation inside a run: shell command in release.yml. Line 49: `run: echo ${{ steps.npm-bump.outputs['release-tag'] }}` — a step output is interpolated directly and unquoted into the shell command string.

Locations:

- `.github/workflows/release.yml:49`

### github-env-injection (severity: high)

Unsanitized inputs written to $GITHUB_OUTPUT without the required `printf '%s' ... | tr -d '\n\r'` sanitization step. (1) `NEW_VERSION` (sourced from inputs['new-version'] via env var) is written directly: `echo "new-version=$NEW_VERSION" >> "$GITHUB_OUTPUT"` (lines ~58 and ~64). (2) `VERSION_TYPE` (sourced from inputs['version-type'] via env var) is written directly: `echo "new-version=$VERSION_TYPE" >> "$GITHUB_OUTPUT"` (line ~61). A newline in either input value could inject arbitrary key=value pairs into the output file.

Locations:

- `action.yml:58`
- `action.yml:61`
- `action.yml:64`

### unpinned-uses (severity: high)

Three uses: references in release.yml use mutable tags or branch names instead of full 40-character SHA digests, making the workflow vulnerable to supply-chain attacks if those refs are moved: (1) `actions/checkout@v6` — tag ref; (2) `actions/setup-node@v6` — tag ref; (3) `bcomnes/npm-bump@master` — branch ref (especially dangerous as branch refs can be updated at any time).

Locations:

- `.github/workflows/release.yml:33`
- `.github/workflows/release.yml:36`
- `.github/workflows/release.yml:41`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unpinned-uses

**Notes:**

Fixed all findings across action.yml and .github/workflows/release.yml:

1. script-injection (action.yml lines 41-42): Moved git-username and git-email inputs into env vars (GIT_USERNAME, GIT_EMAIL) to prevent shell interpolation.

2. script-injection (action.yml line 76): Moved push-version-commit input into env var PUSH_VERSION_COMMIT for safe shell conditional comparison.

3. script-injection (action.yml line 81): Moved publish-cmd input into env var PUBLISH_CMD and used `eval "$PUBLISH_CMD"` to prevent YAML-level injection.

4. github-env-injection (action.yml lines 58, 61, 64): Added `printf '%s' ... | tr -d '\n\r'` sanitization for NEW_VERSION and VERSION_TYPE before writing to $GITHUB_OUTPUT.

5. script-injection (release.yml line 49): Moved step output into env var RELEASE_TAG and used `echo "$RELEASE_TAG"` with proper quoting.

6. unpinned-uses (release.yml lines 33, 36, 41): Pinned actions/checkout@v6 to SHA df4cb1c069e1874edd31b4311f1884172cec0e10, actions/setup-node@v6 to SHA 48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e, and bcomnes/npm-bump@master to SHA 2c111ae6763b625b9d8a2c068b328ea5fc33d72d.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the script-injection vulnerability in the 'publish' step of action.yml (line 100). Replaced `eval "$PUBLISH_CMD"` with a safe array-based execution: `read -ra cmd_args <<< "$PUBLISH_CMD"` followed by `"${cmd_args[@]}"`. This splits the command by whitespace (allowing commands with arguments like `npm publish`) without interpreting shell metacharacters (semicolons, pipes, backticks, etc.), preventing arbitrary code execution. The PUBLISH_CMD env var was already correctly set from the input expression in the env block.

