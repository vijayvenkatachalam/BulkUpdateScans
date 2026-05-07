# Traceable Scan-Suite Admin CLI

Command-line utility for bulk administration of Traceable scan suites. Drives the public (`api.traceable.ai`) and private (`app.traceable.ai`) GraphQL endpoints to **update**, **migrate**, **gap-analyze**, and **delete** scan suites at scale.

Everything runs from a single `main.py` driven by a `config.json` file. Mutations always print + dump the exact GraphQL request that was (or would be) sent, support a hard dry-run mode, and continue on per-suite failures.

---

## Table of contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Subcommands](#subcommands)
  - [`update` — bulk update timeouts and runner labels](#update--bulk-update-timeouts-and-runner-labels)
  - [`migrate` — copy suites from source_env to target_env](#migrate--copy-suites-from-source_env-to-target_env)
  - [`gap-analysis` — create suites for owners with no scan in target_env](#gap-analysis--create-suites-for-owners-with-no-scan-in-target_env)
  - [`delete-source` — clean up source_env after a successful migration](#delete-source--clean-up-source_env-after-a-successful-migration)
  - [`delete-suites` — delete arbitrary suites by ID](#delete-suites--delete-arbitrary-suites-by-id)
- [Dry-run vs. apply](#dry-run-vs-apply)
- [`config.json` reference](#configjson-reference)
- [Output artifacts](#output-artifacts)
- [Operational notes](#operational-notes)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- Python 3.9+
- `requests`
- A Traceable public API token and a Traceable private (UI session) JWT — see `auth` in `config.json`

```bash
python -m venv .venv
source .venv/bin/activate
pip install requests
```

The macOS LibreSSL warning from `urllib3` is harmless. To silence it: `pip install 'urllib3<2'`.

---

## Quick start

```bash
# 1. Drop your tokens into config.json (see config reference below).

# 2. Always start with a dry-run.
python main.py migrate --dry-run

# 3. Inspect the JSON report it produced.
cat migration_report.json | jq '.create_summary, .owners_to_migrate'

# 4. When you're satisfied, apply.
python main.py migrate --apply
```

`--dry-run` and `--apply` work both before and after the subcommand:

```bash
python main.py migrate --dry-run     # works
python main.py --dry-run migrate     # also works
```

`--apply` always wins over `--dry-run` if both are passed. With neither flag, the CLI falls back to `config.dry_run.enabled`.

---

## Subcommands

### `update` — bulk update timeouts and runner labels

Default behavior. Lists every scan suite (optionally filtered by name LIKE/regex), fetches each suite's full configuration, overlays new `idleTimeoutDuration` / `scanTimeoutDuration` / `runnerLabels`, and submits a full-shape `updateScanSuite` mutation.

```bash
python main.py                    # implicit -- back-compat with the original script
python main.py update             # explicit
python main.py update --dry-run   # preview the before/after diff per suite
```

What it touches per suite:

- `advanceConfiguration.idleTimeoutDuration` ← `updates.new_idle_timeout`
- `advanceConfiguration.scanTimeoutDuration` ← `updates.new_scan_timeout`
- `scheduleJobConfiguration.runnerLabels` ← `updates.runner_labels` (also clears `runnerIds`)
- `scheduleJobConfiguration.status` ← `ENABLED` if the suite has any schedule but no status

Failures are logged, written to `output.failed_out` (default `failed_suites.jsonl`), and processing continues with the next suite.

### `migrate` — copy suites from `source_env` to `target_env`

Useful when you cannot change a suite's `environment` in place. The CLI:

1. Lists all suites in `source_env` (env-filtered `searchAst`, public endpoint).
2. Lists all suites in `target_env` (same query, different env literal).
3. Batches both ID lists into `scanSuites` detail queries (private endpoint, `IN` list, default 50 per call) and extracts the **owner ID** from each suite's `selectedAssetFilter`.
4. Diffs by owner ID. For each owner present in source but missing from target, builds a `createScanSuite` mutation from the `migration` template in `config.json`. Only the owner ID and the new suite name vary; everything else (policy, hook, schedule, runner labels, severity, durations, etc.) comes from config.
5. New suite name format: `{OWNER}_{target_env}_{scan_name_suffix}`, e.g. `AD00006850_f5-mirroring_Daily_Passive_Scan`.
6. Writes a JSON report to `migration.report_out` (default `migration_report.json`).

```bash
python main.py migrate --dry-run    # produces migration_report.json with planned creates
python main.py migrate --apply      # fires createScanSuite for each missing owner
```

The migrate command **never deletes** source suites. Run `delete-source` separately, after you've validated the migrated suites.

### `gap-analysis` — create suites for owners with no scan in `target_env`

Identifies API owners that are actively being discovered but have no scan configured in the target environment.

1. Runs the `explore` GraphQL query (private endpoint) over a configurable time window (`gap_analysis.owner_window_hours`, default 24h) to list all distinct owners with `isLearnt=true`, owner `!= "null"`, and `apiDiscoveryState IN [DISCOVERED, UNDER_DISCOVERY]`.
2. Lists all suites in `gap_analysis.target_env`, batches their details, and extracts owner IDs.
3. Diffs: discovered owners − owners with at least one scan in target_env = **gap owners**.
4. For each gap owner, builds a `createScanSuite` mutation using the same `migration` template (so `gap_analysis` reuses the migration template — keeps the suite shape consistent).
5. Writes `gap_analysis.report_out` (default `gap_analysis_report.json`).

```bash
python main.py gap-analysis --dry-run
python main.py gap-analysis --apply
```

### `delete-source` — clean up `source_env` after a successful migration

Safe cleanup: deletes only those `source_env` suites whose owner already has a counterpart in `target_env`. A suite whose owner has no target counterpart is **never** deleted; it appears in the report under `skipped` with `reason: "no_target_counterpart"`. Suites where the owner could not be parsed are skipped with `reason: "owner_not_resolvable"`.

```bash
python main.py delete-source --dry-run   # lists what would be deleted, plus skipped
python main.py delete-source --apply     # batch deleteScanSuites
```

Writes `delete_source_report.json`.

### `delete-suites` — delete arbitrary suites by ID

Generic batch delete. Useful for ad-hoc cleanup or rolling back a specific test create.

```bash
python main.py delete-suites --ids "id1,id2,id3" --dry-run
python main.py delete-suites --ids "id1,id2,id3" --apply
```

---

## Dry-run vs. apply

Three sources of truth, in precedence order:

1. `--apply` on the command line — forces real execution.
2. `--dry-run` on the command line — forces preview-only, no mutations.
3. `config.dry_run.enabled` — fallback when neither flag is passed.

Dry-run still performs **all read queries** (so you can see real diffs) and writes the same JSON report files. It just doesn't fire mutations. Each planned mutation is dumped to `debug.debug_dump_dir` as a `.graphql` + `.json` pair so you can inspect the exact request that would have been sent.

---

## `config.json` reference

The repo's `config.json` is a working template. Sections:

### `endpoints` (required)

```json
"endpoints": {
  "public_gql":  "https://api.traceable.ai/graphql",
  "private_gql": "https://app.traceable.ai/graphql"
}
```

### `auth` (required)

```json
"auth": {
  "public_token": "<API key>",
  "public_use_bearer": false,
  "private_token": "<JWT from app.traceable.ai session>",
  "private_use_bearer": true
}
```

`*_use_bearer` controls whether the token is sent as `Authorization: Bearer <token>` or just `Authorization: <token>`. Public API keys typically don't need `Bearer`; private JWTs do.

### `updates` — used by `update` only

```json
"updates": {
  "new_idle_timeout":   "PT30M",
  "new_scan_timeout":   "PT120M",
  "force_is_learnt_true": true,
  "runner_labels":      ["F5-Runner"]
}
```

### `filters` — used by `update` only

```json
"filters": {
  "scan_suite_name_like":  "Daily_Passive_Scan",
  "scan_suite_name_regex": null
}
```

`scan_suite_name_like` is server-side (passed as `LIKE` to `searchAst`). `scan_suite_name_regex` is a client-side post-filter applied on top.

### `dry_run`

```json
"dry_run": {
  "enabled":    false,
  "max_suites": 200
}
```

`max_suites` caps how many suites the `update` subcommand processes during dry-runs; useful for fast iteration on large tenants.

### `rate_limit`

```json
"rate_limit": {
  "public_min_interval_s":  0.35,
  "private_min_interval_s": 0.35,
  "public_max_retries":     6,
  "private_max_retries":    6
}
```

Minimum spacing between requests per endpoint, plus exponential-backoff retry budget on transient failures (429s, 5xx).

### `debug`

```json
"debug": {
  "print_gql_before_exec": true,
  "print_vars_before_exec": true,
  "dump_gql_to_files":     true,
  "debug_dump_dir":        "debug_requests",
  "max_print_chars":       15000
}
```

When `dump_gql_to_files` is on, every mutation (or planned mutation, in dry-run) is written as `<suite_id_or_action>.graphql` and `<suite_id_or_action>.json` (variables) to `debug_dump_dir`.

### `output`

```json
"output": {
  "failed_out": "failed_suites.jsonl"
}
```

Per-suite failure log, one JSON object per line. Includes stage, error type, error message, and the response payload (if any) at the time of failure.

### `migration` — used by `migrate` and reused by `gap-analysis` for create payload shape

```json
"migration": {
  "source_env": "akamai-poc",
  "target_env": "f5-mirroring",
  "scan_name_suffix": "Daily_Passive_Scan",

  "policy_id": "30ce0c1a-3cfe-46dc-8ace-97937d357f9f",
  "hook_id":   "0712511d-7c05-42ff-a4ec-773709222406",

  "schedule_time":  "18:00:00.000Z",
  "runner_labels": ["F5-Runner"],

  "delay_duration":   "PT0S",
  "idle_timeout":     "PT1800S",
  "scan_timeout":     "PT7200S",
  "test_threads":     20,

  "vuln_severity":      "HIGH",
  "vuln_threshold":     0,
  "vuln_open_duration": "PT604800S",

  "batch_size": 50,
  "report_out": "migration_report.json"
}
```

`batch_size` controls how many suite IDs go into each `scanSuites` `IN` query. The CLI will automatically split a failing batch in half on schema errors (see [Operational notes](#operational-notes)).

### `gap_analysis` — used by `gap-analysis`

```json
"gap_analysis": {
  "target_env":         "f5-mirroring",
  "owner_window_hours": 24,
  "discovery_states":   ["DISCOVERED", "UNDER_DISCOVERY"],
  "explore_limit":      1000,
  "group_limit":        5000,
  "report_out":         "gap_analysis_report.json"
}
```

`explore_limit` is the outer page size for the `explore` query. `group_limit` is the inner `groupBy.groupLimit` (max distinct owners per page).

---

## Output artifacts

Every subcommand emits structured artifacts so you can audit what happened.

| Artifact | Producer | Contents |
|---|---|---|
| `migration_report.json` | `migrate` | Source/target counts, per-owner diff, planned creates, `create_summary` (planned/created/failed) |
| `gap_analysis_report.json` | `gap-analysis` | Discovered owners, owners with scans in target, gaps, `create_summary` |
| `delete_source_report.json` | `delete-source` | `to_delete_ids`, `skipped` (with reason), `delete_result` |
| `failed_suites.jsonl` | `update`, mutation paths | Per-suite failures: stage, error, payload |
| `debug_requests/*.graphql` + `*.json` | All mutating subcommands | Exact GraphQL + variables for every mutation, including dry-runs |

All reports include a `dry_run` flag and a UTC `timestamp`. Dry-run reports are byte-for-byte equivalent in structure to apply reports, just with empty `created` arrays.

---

## Operational notes

### Defensive batch fetching

Some legacy suites have null values in fields the GraphQL schema marks non-nullable (e.g. `AssetSelection.selectedAsset`). When that happens, the server returns a `NullValueInNonNullableField` error and zeros out the **entire batch** response.

Two mitigations are built in:

1. **Trimmed query.** The owner-extraction query for `scanSuites` only requests `selectedAssetFilter.keyOrExpression.key` and `selectedAssetFilter.value` — nothing else from `assetSelections`. The fields most commonly affected by null-non-nullable corruption (`selectedAsset`, `selectionMode`) are deliberately *not* requested.
2. **Recursive halving.** If a batch still fails for any reason, `fetch_suite_details_batch` splits it in half and retries each half (e.g. 50 → 25 → 12 → 6 → 3 → 1). Once it isolates the bad suite, it logs the suite ID, skips it, and continues. The skipped suite ends up in `source_suites_with_unresolved_owner` in the report so you can fix it out-of-band.

In practice you'll see `WARNING` log lines like:

```
fetch_suite_details_batch: batch of 50 failed schema-side, splitting in half (25 / 25)
fetch_suite_details_batch: skipping suite_id=abc-123 due to schema error: ...
```

These are informational, not fatal.

### Owner extraction

For each suite, the CLI inspects `configuration.assetSelections[*].selectedAssetFilter[*]`, looking for a filter whose `keyOrExpression.key == "owner"`. The owner ID is taken from `value[0]`. If that path returns nothing, the CLI falls back to a regex on the suite name (`\bAD\d{6,10}\b`). If both fail, the suite is reported as `unresolvable` and excluded from the diff.

### Rate limiting and retries

Both clients enforce a minimum wall-clock interval between requests (`rate_limit.*_min_interval_s`) and back off exponentially on 429s and 5xx. The retry budget is bounded by `*_max_retries`. Persistent failures bubble up as `FatalGraphQLError` to the per-suite handler, which logs and continues.

### Idempotency and re-runs

`migrate` and `gap-analysis` are safe to re-run. They diff against the current state of `target_env` every time, so already-migrated owners drop out of the work list. The CLI never updates a target-env suite that already exists — it only creates new ones for owners that aren't represented yet.

`delete-source` always re-derives its safe-to-delete list from the current target_env state, so re-running it after a partial migration only touches suites whose owners now have target counterparts.

---

## Troubleshooting

**`unrecognized arguments: --dry-run`**
You're on an older build of `main.py` where global flags only worked before the subcommand. The current build accepts them in either position. Pull the latest `main.py`.

**`GraphQL errors: NullValueInNonNullableField`**
Means a single suite in your tenant has dirty data and the server can't satisfy a non-nullable field. The CLI now handles this automatically (see [Defensive batch fetching](#defensive-batch-fetching)). If you still see it, you're on a build before that fix landed.

**`Could not detect updateScanSuite(update:) input type via introspection`**
Your public token doesn't have schema introspection access. Either grant it or hard-code the input type (look for `_detect_mutation_input_type` in `main.py`).

**Tokens expire mid-run**
Private JWTs from the UI session are short-lived. For long migrations, generate a fresh JWT just before running. There's no automatic refresh.

**`migration` config missing**
`migrate`, `gap-analysis`, and `delete-source` all require the `migration` section in `config.json`. The `update` subcommand does not.

---

## License

Internal tool. No license declared.
