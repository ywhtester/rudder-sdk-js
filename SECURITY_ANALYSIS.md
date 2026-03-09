# Security Vulnerability Analysis

**Repository:** rudder-sdk-js
**Date:** 2026-03-09
**Scope:** CI/CD pipeline configuration + source code

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 5 |
| Medium | 9 |
| Low | 2 |

---

## Critical Findings

### C-1: Arbitrary Remote Code Execution via `curl | bash`

**File:** `.github/workflows/integrations_version_audit.yml` lines 25–28
**Severity:** CRITICAL

```yaml
- name: Install Cursor CLI
  run: |
    curl https://cursor.com/install -fsS | bash
    echo "$HOME/.cursor/bin" >> $GITHUB_PATH
```

Piping a remote script directly into `bash` with no integrity check (no checksum, no signature verification) allows the remote server — or any attacker performing a MITM attack — to execute arbitrary code with full CI/CD privileges. The `-f` flag hides HTTP errors, making silent failures possible.

**Fix:** Download the binary separately, verify its SHA-256 checksum against a pinned value, then execute it. Alternatively, use a pinned GitHub Action that wraps the installation with integrity guarantees.

---

## High Findings

### H-1: Unpinned Third-Party GitHub Action (`unfor19/install-aws-cli-action`)

**Files:** `.github/workflows/deploy.yml:89`, `deploy-npm.yml`, `rollback.yml:61`, `deploy-sanity-suite.yml:111`
**Severity:** HIGH

`unfor19/install-aws-cli-action` is maintained by an individual unaffiliated with AWS. While it is currently pinned to a commit SHA (good practice), the maintainer could retroactively rewrite history or delete the repository, and a compromised account would allow code injection into all workflows that use it.

**Fix:** Replace with the official `aws-actions/configure-aws-credentials` action or install the AWS CLI directly with a pinned version and checksum verification.

---

### H-2: Excessive `contents: write` Permission on Rollback Workflow

**File:** `.github/workflows/rollback.yml` lines 10–12
**Severity:** HIGH

```yaml
permissions:
  id-token: write
  contents: write  # Added to allow creating/updating releases
```

`contents: write` grants the workflow the ability to modify repository content (push commits, modify releases). If this workflow is triggered by an attacker or its steps are compromised, they gain write access to the repository itself.

**Fix:** Scope permissions to the minimum required. If only release assets need updating, use GitHub's Releases API with a scoped token rather than a blanket `contents: write`.

---

### H-3: Secrets Passed Through Environment Variables to Third-Party Actions

**File:** `.github/workflows/deploy-npm.yml` lines 127, 135, 236, 289, 307, 367 (and similar in other deploy workflows)
**Severity:** HIGH

```yaml
env:
  BUGSNAG_API_KEY: ${{ secrets.RS_PROD_BUGSNAG_API_KEY }}
```

Placing secrets in `env:` blocks exposes them to all steps in the job — including any third-party actions — and they may appear in debug logs or be accessible to injected commands.

**Fix:** Pass secrets directly as `with:` inputs to the specific action that needs them, limiting exposure to only that step.

---

### H-4: Dynamic `new Function()` with Partially Controlled Input (Braze)

**File:** `packages/analytics-js-integrations/src/integrations/Braze/nativeSdkLoader.js` lines 11–16
**Severity:** HIGH

```javascript
new Function(
  'return function ' + m.replace(/\./g, '_') + '(){window.brazeQueue.push(arguments); return true}'
)()
```

`m` derives from `BrazeOperationString.split(' ')`, a static constant today. However, the pattern constructs and executes code strings dynamically. If the constant is ever modified, or if the source of `m` changes to incorporate external data, this becomes a direct code-injection vector. CSP policies that block `unsafe-eval` will also break this.

**Fix:** Replace with a lookup table of pre-defined functions keyed by operation name, eliminating runtime code generation entirely.

---

### H-5: Script Injection via GitHub Context Variables in Shell `run:` Steps

**Files:** `.github/workflows/deploy-prod.yml:29`, `deploy-dev.yml:28`, `deploy-staging.yml:31`, `publish-new-release.yml:29`
**Severity:** HIGH

```yaml
run: echo "trigger_source=${{ format('PR <{0}|#{1}> merged by <{2}|{3}>',
  github.event.pull_request.html_url,
  github.event.pull_request.number,
  format('{0}/{1}', github.server_url, github.actor),
  github.actor) }}" >> $GITHUB_OUTPUT
```

`github.actor` is controlled by the GitHub username. A specially crafted username containing `$(...)` or backtick sequences would be expanded by the shell before GitHub's `format()` escaping can prevent it.

**Fix:** Write context values to an intermediate environment variable first (GitHub auto-redacts and sanitises env var assignments), then reference the env var in the shell command:

```yaml
env:
  ACTOR: ${{ github.actor }}
run: echo "trigger_source=... $ACTOR ..." >> $GITHUB_OUTPUT
```

---

## Medium Findings

### M-1: `innerHTML` Assignment Without Sanitisation (Sanity Suite)

**File:** `packages/sanity-suite/src/testBook/TestBook.js` lines 196, 232, 352
**Severity:** MEDIUM

```javascript
this.container.innerHTML = this.joinHtml(this.markupItems);      // line 196
resultContainer.innerHTML = JSON.stringify(normalisedResultData); // line 232
```

Although this is testing/sanity-suite code (not shipped in the production SDK bundle), `innerHTML` assignments without sanitisation can be exploited if test data contains attacker-controlled HTML. Developers running the sanity suite locally or in CI against a compromised data source are at risk.

**Fix:** Use `textContent` for plain text, or `element.appendChild(document.createTextNode(...))`. If HTML is required, use a sanitizer such as DOMPurify.

---

### M-2: Unsanitised URL Assignment to `script.src`

**Files:**
- `packages/analytics-v1.1/src/utils/JSFileLoader.js:23`
- `packages/loading-scripts/src/index.ts:84`
**Severity:** MEDIUM

```javascript
scriptElem.src = url;  // no origin or protocol validation
```

If the URL originates from configuration loaded from an external data plane, an attacker who can modify that configuration (or intercept it over plain HTTP) could cause the SDK to load and execute a malicious script.

**Fix:** Validate that URLs use `https:` and belong to an expected allowlist of domains before assigning to `src`.

---

### M-3: Build-Time API Key Substitution With Insecure Fallback

**Files:**
- `packages/analytics-v1.1/src/features/core/metrics/errorReporting/providers/Bugsnag.js:20`
- `packages/analytics-v1.1/rollup-configs/rollup.utilities.mjs:75`
**Severity:** MEDIUM

```javascript
const API_KEY = '__RS_BUGSNAG_API_KEY__';
// rollup config:
__RS_BUGSNAG_API_KEY__: process.env.BUGSNAG_API_KEY || '{{__RS_BUGSNAG_API_KEY__}}'
```

If the `BUGSNAG_API_KEY` environment variable is not set at build time, the literal placeholder string ships in the production bundle. Any build artifact produced in a misconfigured environment leaks the absence of the key and could confuse monitoring. More importantly, if the key _is_ substituted correctly, it is embedded in plain text in the distributed JS file (visible to any user).

**Fix:** Rotate Bugsnag keys periodically. Consider proxying error reports through a backend endpoint to avoid embedding API keys in client-side code.

---

### M-4: Prototype Pollution Risk Pattern in Braze Loader

**File:** `packages/analytics-js-integrations/src/integrations/Braze/nativeSdkLoader.js:10`
**Severity:** MEDIUM

```javascript
for (var m = s[i], k = a.braze, l = m.split('.'), j = 0; j < l.length - 1; j++)
  k = k[l[j]];
k[l[j]] = new Function(...)();
```

The pattern `k[l[j]] = value` assigns to nested object properties using strings from `m`. While `m` is currently a static constant, a future change that introduces external input into the operation string list would enable prototype pollution via `__proto__` or `constructor` segments.

**Fix:** Add explicit guards: `if (l[j] === '__proto__' || l[j] === 'constructor') continue;` or, better, refactor to a static method map.

---

### M-5: User-Supplied Inputs Written Directly to Files in Workflow

**File:** `.github/workflows/draft-new-release.yml` lines 135–153, 205–215
**Severity:** MEDIUM

```yaml
cat > release-info/release-info.json << EOF
{
  "channel_id": "${{ steps.slack-info.outputs.channel_id }}",
  ...
}
EOF
```

`channel_id` and `thread_ts` are derived by parsing the user-supplied `slack_message_link` input with `sed`. Malformed or adversarial input could corrupt the JSON file, cause incorrect release metadata to be stored, or (in edge cases) inject shell metacharacters.

**Fix:** Use `jq` to construct JSON safely: `jq -n --arg channel "$CHANNEL_ID" '{"channel_id": $channel}'`.

---

### M-6: `JSON.parse` Without Error Handling

**File:** `packages/analytics-js-integrations/src/integrations/GA4_V2/browser.js:22`
**Severity:** MEDIUM

```javascript
const configDetails = JSON.parse(config.configData);
```

Malformed JSON from the configuration source throws an uncaught `SyntaxError`, crashing the GA4 integration silently or loudly depending on the execution context.

**Fix:** Wrap in a try/catch and log a descriptive error.

---

### M-7: AnonymousId Exposed in Third-Party Pixel URLs

**File:** `packages/analytics-js-integrations/src/integrations/DCMFloodlight/browser.js:84`
**Severity:** MEDIUM

```javascript
`&google_hm=${btoa(this.analytics.getAnonymousId())}`
```

The anonymous ID (a persistent user identifier) is sent in a pixel URL query parameter. This means the value is logged in browser history, server access logs of the DCM/Floodlight endpoint, and any network monitoring proxy. Base64 encoding provides no confidentiality.

**Fix:** Evaluate whether passing the anonymous ID to DoubleClick is necessary. If it is, document the privacy implication clearly and ensure it is covered in the privacy policy.

---

### M-8: `postinstall` Script Defined Despite `ignore-scripts=true`

**Files:** `package.json:50`, `.npmrc:3`
**Severity:** MEDIUM

```json
"postinstall": "patch-package"
```

```
ignore-scripts=true
```

The `.npmrc` setting currently prevents the `postinstall` script from running, but this is a fragile arrangement. Any developer who installs without this `.npmrc` (e.g. via `npm install --ignore-scripts=false` or a different npm client) will execute `patch-package`, which modifies files in `node_modules`. If a supply-chain attack compromises `patch-package`, it executes with install-time privileges.

**Fix:** Document this dependency explicitly and consider applying patches at build time via a dedicated script rather than relying on `postinstall`.

---

### M-9: NPM Cache Without Additional Integrity Verification

**Files:** All workflow files using `cache: 'npm'`
**Severity:** MEDIUM (accepted risk)

GitHub Actions npm caching does not re-run `npm ci` integrity checks on the cached `node_modules`. A poisoned cache entry could introduce tampered packages.

**Fix:** Prefer caching only the npm global cache (`~/.npm`) rather than `node_modules`, so `npm ci` still performs lockfile-based integrity verification on each run.

---

## Low Findings

### L-1: `window` Global Namespace Pollution

**Files:**
- `packages/loading-scripts/src/index.ts:11–12`
- `packages/analytics-js-integrations/src/integrations/Bugsnag/browser.js:33`
**Severity:** LOW

The SDK assigns properties directly to `window` (e.g. `window.bugsnagClient`). Third-party scripts on the same page could overwrite these properties before the SDK checks them, potentially redirecting SDK behaviour.

**Fix:** Use a Symbol-keyed property or a namespaced object, and perform an existence check before assigning.

---

### L-2: Predictable `/tmp` Path in CI (TOCTOU Race)

**Files:** `.github/workflows/deploy.yml` lines 167–178 and `deploy-npm.yml`
**Severity:** LOW

```bash
tmp_file="/tmp/legacy_${{ env.INTEGRATIONS_ZIP_FILE }}"
tar -czvf "$tmp_file" ...
mv "$tmp_file" ...
```

Temporary files are created at predictable paths under `/tmp`. On a shared runner, a concurrent process could pre-create or symlink the path (TOCTOU). GitHub-hosted runners are ephemeral and isolated, mitigating the practical risk, but the pattern is bad practice.

**Fix:** Use `mktemp` to create temporary files with unpredictable names: `tmp_file=$(mktemp /tmp/legacy.XXXXXX)`.

---

## Positive Security Controls Observed

The following good practices were noted and should be maintained:

- **Step Security Harden Runner** is used consistently across all workflows — restricts egress and syscalls.
- **All GitHub Actions are pinned to commit SHAs** — prevents tag-based supply chain attacks.
- **`ignore-scripts=true` in `.npmrc`** — prevents postinstall code execution during dependency installation.
- **No `pull_request_target` workflows** — eliminates a common vector for untrusted-code execution on privileged contexts.
- **Actor allowlists on sensitive workflows** — limits who can trigger deployments.
- **No `eval()` usage detected** in production code.
- **No `document.write()` usage detected.**
- **No unescaped `postMessage` handlers** without origin validation detected.

---

## Recommended Remediation Priority

1. **C-1** — Replace `curl | bash` immediately; supply-chain risk on every CI run.
2. **H-5** — Fix shell injection via GitHub context variables; low effort, high impact.
3. **H-3** — Move secrets out of `env:` blocks.
4. **H-4** — Refactor Braze dynamic `new Function()` to a static dispatch table.
5. **H-1** — Replace `unfor19/install-aws-cli-action` with the official AWS action.
6. **H-2** — Narrow `rollback.yml` permissions.
7. **M-1 through M-9** — Address in order of exposure surface.
