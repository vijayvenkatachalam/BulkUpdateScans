#!/usr/bin/env python3
"""
Traceable scan-suite admin CLI (public/private endpoints).

Subcommands:
  update         Bulk update existing scan suites (idle/scan timeouts, runnerLabels).
                 [Default if no subcommand is provided -- backward compatible.]
  migrate        Functionality 1: migrate scan suites from source_env to target_env.
                 - Lists suites in source_env and target_env (env-filtered searchAst)
                 - Diffs by owner ID (extracted from selectedAssetFilter)
                 - For each owner missing in target_env, runs createScanSuite using a
                   template defined in config.migration (only owner ID + new name vary)
                 - Writes a JSON report (dry-run or apply)
  gap-analysis   Functionality 2: find owners with no scan config in target_env.
                 - Runs explore over a configurable time window to list all owners
                 - Lists existing target_env suites and extracts owners
                 - Diffs and (optionally) creates suites for missing owners using the
                   same migration template
                 - Writes a JSON report (dry-run or apply)
  delete-suites  Delete arbitrary scan suites by ID (--ids "id1,id2"). Validation tool.
  delete-source  Delete ALL suites in source_env that have an owner-counterpart in
                 target_env (i.e. safe post-migration cleanup). Dry-run supported.

Common flags:
  --config PATH     Path to config.json (default: config.json)
  --dry-run         Force dry-run (overrides config.dry_run.enabled)
  --apply           Force apply  (overrides config.dry_run.enabled). --apply wins if both passed.

Robustness:
- Config file driven (JSON)
- Schema introspection to detect correct input type for updateScanSuite(update:) and
  createScanSuite(create:)
- Variable-based mutations where supported; safe inline literals otherwise
- Dumps exact mutation + variables per suite to debug_dump_dir
- Rate limiting + exponential backoff + jitter
- DRY_RUN mode supported on all mutation paths
- Continues on per-suite failures (logs + writes failed_suites.jsonl)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

# -------------------------------------------------------------------------------------------------
# GraphQL queries
# -------------------------------------------------------------------------------------------------

# Query 1 (public): list scan suite ids (paged) + return suite name for optional local regex filtering
QUERY1_SEARCH_AST_TEMPLATE = r"""
query ListScanSuitesFromScans($limit: Int!, $offset: Int!) {
  searchAst(
    astDataSource: SCANS
    limit: $limit
    offset: $offset
    filterBy: [
      { key: SCAN_RUN_NUMBER, operator: GREATER_THAN_OR_EQUAL_TO, value: 0 }
      __NAME_LIKE_FILTER__
    ]
    orderBy: { key: SCAN_START_TIME, direction: DESC }
    join: {
      subQuery: {
        selections: [SCAN_SUITE_ID]
        aggregations: [{ key: SCAN_RUN_NUMBER, aggregation: MAX }]
        groupBy: [{ key: SCAN_SUITE_ID }]
      }
      joinConditions: [
        { mainQueryKey: SCAN_SUITE_ID, operator: EQUALS, subQueryKey: SCAN_SUITE_ID }
        { mainQueryKey: SCAN_RUN_NUMBER, operator: EQUALS, subQueryKey: SCAN_RUN_NUMBER }
      ]
    }
  ) {
    total
    results {
      SCAN_SUITE_ID: selection(key: SCAN_SUITE_ID) { value type __typename }
      SCAN_SUITE_NAME: selection(key: SCAN_SUITE_NAME) { value type __typename }
      __typename
    }
    __typename
  }
}
"""


# Query 2 (private): fetch suite detail by id (inline to avoid schema typing mismatch issues)
QUERY2_SCAN_SUITES_TEMPLATE = r"""
{{
  scanSuites(
    filterBy: [{{key: SCAN_SUITE_IDS, operator: IN, value: ["{suite_id}"]}}]
  ) {{
    count
    total
    results {{
      scanSuite {{
        id
        name
        description
        environment
        advanceConfiguration {{
          delayDurationBetweenRequests
          idleTimeoutDuration
          scanTimeoutDuration
          totalTestExecutionThreads
          __typename
        }}
        configuration {{
          assetSelections {{
            selectedAsset
            selectionMode
            endpoint {{
              idPredicates {{ relationalOperator value __typename }}
              labelPredicates {{ relationalOperator value __typename }}
              urlPredicates {{ relationalOperator value __typename }}
              methodTypePredicates {{ relationalOperator value __typename }}
              apiTypePredicates {{ relationalOperator value __typename }}
              namePredicates {{ relationalOperator value __typename }}
              ownerPredicates {{ relationalOperator value __typename }}
              protocolTypePredicates {{ relationalOperator value __typename }}
              __typename
            }}
            service {{
              idPredicates {{ relationalOperator value __typename }}
              labelPredicates {{ relationalOperator value __typename }}
              namePredicates {{ relationalOperator value __typename }}
              __typename
            }}
            selectedAssetFilter {{
              key
              keyOrExpression: keyExpression {{ key subpath __typename }}
              operator
              type
              value
              __typename
            }}
            __typename
          }}
          incrementalScanConfiguration {{
            isEnabled
            lookBackDuration
            __typename
          }}
          policyId
          targetUrl
          trafficConfiguration {{
            openApiSpecsIds
            wsdlSpecsIds
            generationTrafficType
            replayTraffic {{ trafficDuration __typename }}
            webCrawlerDiscoveryConfiguration {{
              webCrawlerScope {{ seedUrls __typename }}
              webCrawlerLoginDetails {{ loginUsername loginPassword __typename }}
              __typename
            }}
            postmanCollectionDetailsList {{ environmentDocumentId postmanCollectionId __typename }}
            openApiSpecDependencyGraphYaml
            graphqlSchemaDetailsList {{ graphqlIntrospectionEnabled graphqlSchemaId __typename }}
            __typename
          }}
          trafficEnvironment
          baseScanId
          spanFilters {{
            conditions {{
              keyValuePredicate {{
                keyPredicate {{ relationalOperator value __typename }}
                valuePredicate {{ relationalOperator value __typename }}
                __typename
              }}
              location
              __typename
            }}
            __typename
          }}
          __typename
        }}
        hookConfiguration {{
          hookDetails {{ hookId __typename }}
          __typename
        }}
        scanEvaluationCriteriaConfiguration {{
          scanEvaluationCriteriaDetails {{
            scanEvaluationCriteriaId
            inlineScanEvaluationCriteriaDetails {{
              expression {{ allEvaluateTrue __typename }}
              rules {{
                assetScope {{
                  assetSelection {{
                    selectAllAssets {{ isEnabled __typename }}
                    selectNewAssets {{ isEnabled __typename }}
                    __typename
                  }}
                  assetType
                  __typename
                }}
                vulnerabilityScopeAndEvaluation {{
                  severity
                  operator
                  threshold
                  vulnerabilitySelection {{
                    selectAnyVulnerability {{ isEnabled __typename }}
                    selectNewVulnerabilities {{ isEnabled __typename }}
                    __typename
                  }}
                  vulnerabilityDurationScope {{
                    maximumVulnerabilityDuration {{ vulnerabilityOpenDuration __typename }}
                    __typename
                  }}
                  __typename
                }}
                __typename
              }}
              __typename
            }}
            __typename
          }}
          __typename
        }}
        scheduleJobConfiguration {{
          name
          status
          runnerIds
          runnerLabels
          dailySchedule {{ scheduledTime __typename }}
          monthlySchedule {{
            scheduledMonthDays {{ scheduledDayNumbers __typename }}
            scheduledTime
            __typename
          }}
          weeklySchedule {{ scheduledTime scheduledDays __typename }}
          __typename
        }}
        integrationDetails {{
          snykIntegrationDetails {{ organizationId projectIds __typename }}
          __typename
        }}
        __typename
      }}
      __typename
    }}
    __typename
  }}
}}
"""

# Schema introspection: detect updateScanSuite(update:) input type
INTROSPECT_UPDATE_INPUT_TYPE = r"""
query IntrospectUpdateScanSuiteArg {
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType { kind name ofType { kind name ofType { kind name } } }
          }
        }
      }
    }
  }
}
"""

# -------------------------------------------------------------------------------------------------
# GraphQL templates: env-filtered scan listing (Functionality 1 + 2)
# -------------------------------------------------------------------------------------------------

# Lists scan suites filtered by ENVIRONMENT (and optionally by name LIKE).
# We embed the ENV list and name filter as GQL literals (placeholders below) because
# the API expects scalar/JSON-ish values for `value:` rather than typed variables.
QUERY_SCANS_BY_ENV_TEMPLATE = r"""
query ListScansByEnv($limit: Int!, $offset: Int!) {
  searchAst(
    astDataSource: SCANS
    limit: $limit
    offset: $offset
    filterBy: [
      { key: SCAN_RUN_NUMBER, operator: GREATER_THAN_OR_EQUAL_TO, value: 0 }
      { key: ENVIRONMENT, operator: IN, value: __ENV_LIST__ }
      __NAME_LIKE_FILTER__
    ]
    orderBy: { key: SCAN_START_TIME, direction: DESC }
    join: {
      subQuery: {
        selections: [SCAN_SUITE_ID]
        aggregations: [{ key: SCAN_RUN_NUMBER, aggregation: MAX }]
        groupBy: [{ key: SCAN_SUITE_ID }]
      }
      joinConditions: [
        { mainQueryKey: SCAN_SUITE_ID, operator: EQUALS, subQueryKey: SCAN_SUITE_ID }
        { mainQueryKey: SCAN_RUN_NUMBER, operator: EQUALS, subQueryKey: SCAN_RUN_NUMBER }
      ]
    }
  ) {
    total
    results {
      SCAN_SUITE_ID:   selection(key: SCAN_SUITE_ID)   { value type __typename }
      SCAN_SUITE_NAME: selection(key: SCAN_SUITE_NAME) { value type __typename }
      ENVIRONMENT:     selection(key: ENVIRONMENT)     { value type __typename }
      __typename
    }
    __typename
  }
}
"""

# Slim scanSuites detail query that takes a list of suite IDs.
# Used by migration / gap-analysis to extract the owner ID from selectedAssetFilter.
#
# IMPORTANT: We deliberately query the MINIMUM set of fields needed to extract owner.
# In particular we do NOT request `selectedAsset` or `selectionMode` -- those are
# non-nullable enums in the schema, and legacy/dirty suite records can have null values
# there, causing the whole batch query to fail with a NullValueInNonNullableField error.
# By only requesting `selectedAssetFilter.keyOrExpression.key` + `value`, we sidestep
# any null-non-nullable issues on those fields.
QUERY_SCAN_SUITES_DETAILS_BATCH_TEMPLATE = r"""
{
  scanSuites(
    filterBy: [{key: SCAN_SUITE_IDS, operator: IN, value: __SUITE_IDS_LIST__}]
  ) {
    results {
      scanSuite {
        id
        name
        environment
        configuration {
          assetSelections {
            selectedAssetFilter {
              keyOrExpression: keyExpression { key }
              value
            }
          }
        }
      }
    }
  }
}
"""

# -------------------------------------------------------------------------------------------------
# GraphQL templates: createScanSuite + deleteScanSuites (Functionality 1 + 2)
# -------------------------------------------------------------------------------------------------

CREATE_SUITE_MUTATION_TEMPLATE = r"""
mutation CreateScanSuite($create: __CREATE_INPUT_TYPE__!) {
  createScanSuite(create: $create) {
    id
    __typename
  }
}
"""

# Delete is built inline (literal IDs) because the schema's list element type for
# scanSuiteIdList is unknown and the user-supplied reference uses inline literals.
# See build_delete_suites_mutation().

# -------------------------------------------------------------------------------------------------
# GraphQL templates: explore (Functionality 2 owner discovery)
# -------------------------------------------------------------------------------------------------
# Built inline by build_explore_owners_query() so we can interpolate a JSON-list of
# discovery states and ISO-8601 timestamps without worrying about scalar type names.

# -------------------------------------------------------------------------------------------------
# Types + errors
# -------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class GraphQLRequest:
    query: str
    variables: Dict[str, Any]

class TransientError(RuntimeError):
    pass

class FatalGraphQLError(RuntimeError):
    pass
# -------------------------------------------------------------------------------------------------
# Config
# -------------------------------------------------------------------------------------------------
@dataclass
class AppConfig:
    public_gql: str
    private_gql: str

    public_token: str
    public_use_bearer: bool
    private_token: str
    private_use_bearer: bool

    new_idle_timeout: str
    new_scan_timeout: str

    force_is_learnt_true: bool
    runner_labels: Optional[List[str]]

    scan_suite_name_like: Optional[str]
    scan_suite_name_regex: Optional[str]

    dry_run: bool
    dry_run_max_suites: Optional[int]

    public_min_interval_s: float
    private_min_interval_s: float
    public_max_retries: int
    private_max_retries: int

    print_gql_before_exec: bool
    print_vars_before_exec: bool
    dump_gql_to_files: bool
    debug_dump_dir: Path
    max_print_chars: int

    failed_out: str

    # Optional sub-configs (Functionality 1 + 2). Loaded from config.json if present.
    migration: Optional["MigrationConfig"] = None
    gap_analysis: Optional["GapAnalysisConfig"] = None


@dataclass
class MigrationConfig:
    """Config for `migrate` (Functionality 1) and reused by `gap-analysis` create flow."""
    source_env: str
    target_env: str
    scan_name_suffix: str          # e.g. "Daily_Passive_Scan" -> appended after "{owner}_{target_env}_"
    policy_id: str
    hook_id: str
    schedule_time: str             # e.g. "18:00:00.000Z"
    runner_labels: List[str]
    delay_duration: str            # e.g. "PT0S"
    idle_timeout: str              # e.g. "PT1800S"
    scan_timeout: str              # e.g. "PT7200S"
    test_threads: int              # e.g. 20
    vuln_severity: str             # e.g. "HIGH"
    vuln_threshold: int            # e.g. 0
    vuln_open_duration: str        # e.g. "PT604800S"
    batch_size: int                # batch size for scanSuites detail fetch
    report_out: str                # path to write the dry-run / apply JSON report


@dataclass
class GapAnalysisConfig:
    """Config for `gap-analysis` (Functionality 2)."""
    target_env: str                # target env to check / create suites in
    owner_window_hours: int        # explore time window (hours back from now)
    discovery_states: List[str]    # e.g. ["DISCOVERED", "UNDER_DISCOVERY"]
    explore_limit: int             # outer `limit` for explore (per page)
    group_limit: int               # inner `groupBy.groupLimit` for explore (max distinct owners)
    report_out: str                # path to write the dry-run / apply JSON report

def _require(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise RuntimeError(f"Missing required config key: {path}")
        cur = cur[part]
    return cur

def load_config(path: str) -> AppConfig:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))

    public_gql = _require(raw, "endpoints.public_gql")
    private_gql = _require(raw, "endpoints.private_gql")

    public_token = _require(raw, "auth.public_token")
    private_token = _require(raw, "auth.private_token")
    public_use_bearer = bool(raw.get("auth", {}).get("public_use_bearer", False))
    private_use_bearer = bool(raw.get("auth", {}).get("private_use_bearer", True))

    new_idle_timeout = _require(raw, "updates.new_idle_timeout")
    new_scan_timeout = _require(raw, "updates.new_scan_timeout")

    force_is_learnt_true = bool(raw.get("updates", {}).get("force_is_learnt_true", True))
    runner_labels = raw.get("updates", {}).get("runner_labels", None)
    if runner_labels is not None and not isinstance(runner_labels, list):
        raise RuntimeError("updates.runner_labels must be a list of strings or null")

    scan_suite_name_like = raw.get("filters", {}).get("scan_suite_name_like", None)
    scan_suite_name_regex = raw.get("filters", {}).get("scan_suite_name_regex", None)

    dry_run = bool(raw.get("dry_run", {}).get("enabled", False))
    dry_run_max_suites = raw.get("dry_run", {}).get("max_suites", None)

    public_min_interval_s = float(raw.get("rate_limit", {}).get("public_min_interval_s", 0.35))
    private_min_interval_s = float(raw.get("rate_limit", {}).get("private_min_interval_s", 0.35))
    public_max_retries = int(raw.get("rate_limit", {}).get("public_max_retries", 6))
    private_max_retries = int(raw.get("rate_limit", {}).get("private_max_retries", 6))

    print_gql_before_exec = bool(raw.get("debug", {}).get("print_gql_before_exec", True))
    print_vars_before_exec = bool(raw.get("debug", {}).get("print_vars_before_exec", True))
    dump_gql_to_files = bool(raw.get("debug", {}).get("dump_gql_to_files", True))
    debug_dump_dir = Path(raw.get("debug", {}).get("debug_dump_dir", "debug_requests"))
    max_print_chars = int(raw.get("debug", {}).get("max_print_chars", 12000))

    failed_out = raw.get("output", {}).get("failed_out", "failed_suites.jsonl")

    # ---- migration config (optional; required only if `migrate` subcommand is used) ----
    migration_cfg: Optional[MigrationConfig] = None
    mig_raw = raw.get("migration")
    if isinstance(mig_raw, dict):
        runner_labels_mig = mig_raw.get("runner_labels", [])
        if not isinstance(runner_labels_mig, list):
            raise RuntimeError("migration.runner_labels must be a list of strings")
        migration_cfg = MigrationConfig(
            source_env=str(_require(raw, "migration.source_env")),
            target_env=str(_require(raw, "migration.target_env")),
            scan_name_suffix=str(mig_raw.get("scan_name_suffix", "Daily_Passive_Scan")),
            policy_id=str(_require(raw, "migration.policy_id")),
            hook_id=str(_require(raw, "migration.hook_id")),
            schedule_time=str(mig_raw.get("schedule_time", "18:00:00.000Z")),
            runner_labels=[str(x) for x in runner_labels_mig],
            delay_duration=str(mig_raw.get("delay_duration", "PT0S")),
            idle_timeout=str(mig_raw.get("idle_timeout", "PT1800S")),
            scan_timeout=str(mig_raw.get("scan_timeout", "PT7200S")),
            test_threads=int(mig_raw.get("test_threads", 20)),
            vuln_severity=str(mig_raw.get("vuln_severity", "HIGH")),
            vuln_threshold=int(mig_raw.get("vuln_threshold", 0)),
            vuln_open_duration=str(mig_raw.get("vuln_open_duration", "PT604800S")),
            batch_size=int(mig_raw.get("batch_size", 50)),
            report_out=str(mig_raw.get("report_out", "migration_report.json")),
        )

    # ---- gap-analysis config (optional; required only if `gap-analysis` subcommand is used) ----
    gap_cfg: Optional[GapAnalysisConfig] = None
    gap_raw = raw.get("gap_analysis")
    if isinstance(gap_raw, dict):
        states = gap_raw.get("discovery_states", ["DISCOVERED", "UNDER_DISCOVERY"])
        if not isinstance(states, list):
            raise RuntimeError("gap_analysis.discovery_states must be a list of strings")
        gap_cfg = GapAnalysisConfig(
            target_env=str(_require(raw, "gap_analysis.target_env")),
            owner_window_hours=int(gap_raw.get("owner_window_hours", 24)),
            discovery_states=[str(s) for s in states],
            explore_limit=int(gap_raw.get("explore_limit", 1000)),
            group_limit=int(gap_raw.get("group_limit", 5000)),
            report_out=str(gap_raw.get("report_out", "gap_analysis_report.json")),
        )

    # Optional: allow env override without forcing you to store tokens in config.json
    public_token = os.getenv("TRACEABLE_PUBLIC_TOKEN", public_token)
    private_token = os.getenv("TRACEABLE_PRIVATE_TOKEN", private_token)

    if not public_token.strip() or public_token.strip() == "REPLACE_ME":
        raise RuntimeError("Public token missing. Set auth.public_token in config or TRACEABLE_PUBLIC_TOKEN env var.")
    if not private_token.strip() or private_token.strip() == "REPLACE_ME":
        raise RuntimeError("Private token missing. Set auth.private_token in config or TRACEABLE_PRIVATE_TOKEN env var.")

    # Validate regex early (if provided)
    if scan_suite_name_regex:
        try:
            re.compile(scan_suite_name_regex)
        except re.error as e:
            raise RuntimeError(f"Invalid filters.scan_suite_name_regex: {e}") from e

    return AppConfig(
        public_gql=public_gql,
        private_gql=private_gql,

        public_token=public_token,
        public_use_bearer=public_use_bearer,
        private_token=private_token,
        private_use_bearer=private_use_bearer,

        new_idle_timeout=new_idle_timeout,
        new_scan_timeout=new_scan_timeout,

        force_is_learnt_true=force_is_learnt_true,
        runner_labels=runner_labels,

        scan_suite_name_like=scan_suite_name_like,
        scan_suite_name_regex=scan_suite_name_regex,

        dry_run=dry_run,
        dry_run_max_suites=dry_run_max_suites,

        public_min_interval_s=public_min_interval_s,
        private_min_interval_s=private_min_interval_s,
        public_max_retries=public_max_retries,
        private_max_retries=private_max_retries,

        print_gql_before_exec=print_gql_before_exec,
        print_vars_before_exec=print_vars_before_exec,
        dump_gql_to_files=dump_gql_to_files,
        debug_dump_dir=debug_dump_dir,
        max_print_chars=max_print_chars,

        failed_out=failed_out,

        migration=migration_cfg,
        gap_analysis=gap_cfg,
    )

# -------------------------------------------------------------------------------------------------
# Debug helpers
# -------------------------------------------------------------------------------------------------
SENSITIVE_KEYS = {"loginPassword", "authorization", "token", "jwt", "password", "clientSecret", "secret"}

def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in SENSITIVE_KEYS:
                out[k] = "***REDACTED***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj

def gql_escape_string(s: str) -> str:
    # safe enough for embedding into "..."
    return s.replace("\\", "\\\\").replace('"', '\\"')

def dump_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def dump_json(path: Path, content: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, indent=2), encoding="utf-8")

def print_request_artifacts(cfg: AppConfig, query: str, variables: dict) -> None:
    safe_vars = redact(variables)
    if cfg.print_gql_before_exec:
        s = query.strip()
        print("\n--- GraphQL MUTATION (about to execute) ---")
        print(s[: cfg.max_print_chars] + ("...\n" if len(s) > cfg.max_print_chars else "\n"))
    if cfg.print_vars_before_exec:
        s = json.dumps(safe_vars, indent=2)
        print("--- GraphQL VARIABLES ---")
        print(s[: cfg.max_print_chars] + ("...\n" if len(s) > cfg.max_print_chars else "\n"))

def dump_request_artifacts(cfg: AppConfig, suite_id: str, query: str, variables: dict) -> None:
    if not cfg.dump_gql_to_files:
        return
    safe_vars = redact(variables)
    dump_text(cfg.debug_dump_dir / f"{suite_id}_updateScanSuite.graphql", query)
    dump_json(cfg.debug_dump_dir / f"{suite_id}_variables.json", safe_vars)

def dump_failure_artifacts(cfg: AppConfig, suite_id: str, query: str, variables: dict, response_payload: dict) -> None:
    ts = int(time.time())
    dump_text(cfg.debug_dump_dir / f"FAILED_{suite_id}_{ts}_mutation.graphql", query)
    dump_json(cfg.debug_dump_dir / f"FAILED_{suite_id}_{ts}_variables.json", redact(variables))
    dump_json(cfg.debug_dump_dir / f"FAILED_{suite_id}_{ts}_response.json", response_payload)

# -------------------------------------------------------------------------------------------------
# GraphQL client
# -------------------------------------------------------------------------------------------------
class GraphQLClient:
    def __init__(
        self,
        endpoint: str,
        headers: Dict[str, str],
        *,
        timeout_s: float = 45.0,
        min_interval_s: float = 0.35,
        max_retries: int = 6,
        backoff_base_s: float = 0.8,
        backoff_max_s: float = 20.0,
    ) -> None:
        self.endpoint = endpoint
        self.headers = headers
        self.timeout_s = timeout_s
        self.min_interval_s = min_interval_s
        self.max_retries = max_retries
        self.backoff_base_s = backoff_base_s
        self.backoff_max_s = backoff_max_s
        self._last_call_at = 0.0
        self._session = requests.Session()

    def execute(self, req: GraphQLRequest) -> Dict[str, Any]:
        attempt = 0
        while True:
            attempt += 1
            self._rate_limit()

            try:
                resp = self._session.post(
                    self.endpoint,
                    headers=self.headers,
                    json={"query": req.query, "variables": req.variables},
                    timeout=self.timeout_s,
                )
                self._last_call_at = time.time()

                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    raise TransientError(f"Transient HTTP {resp.status_code}: {resp.text[:800]}")

                resp.raise_for_status()
                payload = resp.json()

                if isinstance(payload, dict) and payload.get("errors"):
                    errors = payload["errors"]
                    if self._is_validation_error(errors):
                        raise FatalGraphQLError(f"GraphQL validation errors: {errors}")
                    if self._looks_transient_gql_error(errors):
                        raise TransientError(f"Transient GraphQL errors: {errors}")
                    raise FatalGraphQLError(f"GraphQL errors: {errors}")

                return payload

            except (requests.Timeout, requests.ConnectionError, TransientError) as e:
                if attempt > self.max_retries:
                    raise RuntimeError(f"Exceeded retries ({self.max_retries}). Last error: {e}") from e
                sleep_s = self._backoff(attempt)
                logging.warning("Attempt %s/%s failed (%s). Backing off %.2fs",
                                attempt, self.max_retries, e, sleep_s)
                time.sleep(sleep_s)

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_call_at
        if elapsed < self.min_interval_s:
            time.sleep(self.min_interval_s - elapsed)

    def _backoff(self, attempt: int) -> float:
        exp = self.backoff_base_s * (2 ** (attempt - 1))
        exp = min(exp, self.backoff_max_s)
        jitter = random.uniform(0.0, 0.35 * exp)
        return exp + jitter

    @staticmethod
    def _looks_transient_gql_error(errors: Any) -> bool:
        s = json.dumps(errors) if not isinstance(errors, str) else errors
        s = s.lower()
        return any(k in s for k in ["rate", "throttle", "too many", "timeout", "temporarily", "unavailable"])

    @staticmethod
    def _is_validation_error(errors: Any) -> bool:
        if not isinstance(errors, list):
            return False
        for e in errors:
            msg = (e.get("message") or "").lower()
            cls = ((e.get("extensions") or {}).get("classification") or "").lower()
            if (
                "bad request" in msg
                or "invalid input" in msg
                or "validation error" in msg
                or cls == "validationerror"
            ):
                return True
        return False

# -------------------------------------------------------------------------------------------------
# Normalization helpers
# -------------------------------------------------------------------------------------------------
def strip_typename(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: strip_typename(v) for k, v in obj.items() if k != "__typename"}
    if isinstance(obj, list):
        return [strip_typename(x) for x in obj]
    return obj

def prune_nones(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if v is None:
                continue
            out[k] = prune_nones(v)
        return out
    if isinstance(obj, list):
        return [prune_nones(x) for x in obj if x is not None]
    return obj

TIME_HHMMZ = re.compile(r"^\d{2}:\d{2}Z$")
TIME_HHMMSSZ = re.compile(r"^\d{2}:\d{2}:\d{2}Z$")
TIME_WITH_MILLISZ = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{3}Z$")

def normalize_scheduled_time(value: Optional[str]) -> Optional[str]:
    if not value or not isinstance(value, str):
        return value
    if TIME_WITH_MILLISZ.match(value):
        return value
    if TIME_HHMMZ.match(value):
        return value.replace("Z", ":00.000Z")
    if TIME_HHMMSSZ.match(value):
        return value.replace("Z", ".000Z")
    return value

def normalize_filter(f: Dict[str, Any]) -> Dict[str, Any]:
    f = strip_typename(f)
    key_expr = f.get("keyExpression") or f.get("keyOrExpression") or f.get("keyExpression")
    out: Dict[str, Any] = {
        "keyExpression": key_expr,
        "operator": f.get("operator"),
        "type": f.get("type"),
        "value": f.get("value"),
    }
    return prune_nones(out)

def normalize_predicate_list(preds: Any) -> Any:
    if preds is None:
        return None
    if not isinstance(preds, list):
        return None
    out = []
    for p in preds:
        if not isinstance(p, dict):
            continue
        p2 = prune_nones(strip_typename(p))
        if p2:
            out.append(p2)
    return out or None

def normalize_endpoint_or_service(obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not obj:
        return None
    obj = strip_typename(obj)
    out: Dict[str, Any] = {}
    for key in [
        "idPredicates",
        "labelPredicates",
        "urlPredicates",
        "methodTypePredicates",
        "apiTypePredicates",
        "namePredicates",
        "ownerPredicates",
        "protocolTypePredicates",
    ]:
        if key in obj:
            out[key] = normalize_predicate_list(obj.get(key))
    return prune_nones(out) or None

def _is_islearnt_filter(f: Dict[str, Any]) -> bool:
    if not isinstance(f, dict):
        return False
    ke = f.get("keyExpression") or {}
    return isinstance(ke, dict) and ke.get("key") == "isLearnt"

def enforce_islearnt_true_on_filter_rule(cfg: AppConfig, asset_sel_out: Dict[str, Any]) -> Dict[str, Any]:
    if not cfg.force_is_learnt_true:
        return asset_sel_out
    if asset_sel_out.get("selectedAsset") != "FILTER_RULE":
        return asset_sel_out
    if asset_sel_out.get("selectionMode") != "INCLUDE":
        return asset_sel_out

    force_filter = {
        "keyExpression": {"key": "isLearnt"},
        "operator": "EQUALS",
        "type": "ATTRIBUTE",
        "value": True,
    }

    filters = asset_sel_out.get("selectedAssetFilter") or []
    if not isinstance(filters, list):
        filters = []

    filters = [f for f in filters if not _is_islearnt_filter(f)]
    filters.insert(0, force_filter)
    asset_sel_out["selectedAssetFilter"] = filters
    return asset_sel_out

def normalize_asset_selections(cfg: AppConfig, asset_selections: Any) -> List[Dict[str, Any]]:
    if not asset_selections or not isinstance(asset_selections, list):
        return []

    out: List[Dict[str, Any]] = []
    for sel in asset_selections:
        if not isinstance(sel, dict):
            continue
        sel = strip_typename(sel)
        sel_out: Dict[str, Any] = {
            "selectedAsset": sel.get("selectedAsset"),
            "selectionMode": sel.get("selectionMode"),
        }

        sel_out["endpoint"] = normalize_endpoint_or_service(sel.get("endpoint"))
        sel_out["service"] = normalize_endpoint_or_service(sel.get("service"))

        filters = sel.get("selectedAssetFilter")
        if isinstance(filters, list):
            sel_out["selectedAssetFilter"] = [normalize_filter(f) for f in filters if isinstance(f, dict)]
        else:
            sel_out["selectedAssetFilter"] = None

        sel_out = prune_nones(sel_out)
        sel_out = enforce_islearnt_true_on_filter_rule(cfg, sel_out)
        out.append(sel_out)

    return out

def normalize_configuration(cfg: AppConfig, suite_cfg: Dict[str, Any]) -> Dict[str, Any]:
    suite_cfg = strip_typename(suite_cfg or {})
    out: Dict[str, Any] = {}

    out["assetSelections"] = normalize_asset_selections(cfg, suite_cfg.get("assetSelections"))
    out["incrementalScanConfiguration"] = prune_nones(strip_typename(suite_cfg.get("incrementalScanConfiguration") or {})) or None
    out["policyId"] = suite_cfg.get("policyId")
    out["targetUrl"] = suite_cfg.get("targetUrl")
    out["trafficEnvironment"] = suite_cfg.get("trafficEnvironment")
    out["baseScanId"] = suite_cfg.get("baseScanId")

    traffic = strip_typename(suite_cfg.get("trafficConfiguration") or {})
    out["trafficConfiguration"] = prune_nones(traffic) or None

    span_filters = strip_typename(suite_cfg.get("spanFilters") or {})
    out["spanFilters"] = prune_nones(span_filters) or None

    return prune_nones(out)

def normalize_hook_configuration(hc: Dict[str, Any]) -> Dict[str, Any]:
    hc = strip_typename(hc or {})
    hook_details = hc.get("hookDetails") or []
    out_details = []
    if isinstance(hook_details, list):
        for h in hook_details:
            if isinstance(h, dict) and h.get("hookId"):
                out_details.append({"hookId": h["hookId"]})
    return {"hookDetails": out_details}

def normalize_scan_eval_criteria(sec: Dict[str, Any]) -> Dict[str, Any]:
    sec = strip_typename(sec or {})
    details = sec.get("scanEvaluationCriteriaDetails") or []
    out_details: List[Dict[str, Any]] = []

    if isinstance(details, list):
        for d in details:
            if not isinstance(d, dict):
                continue
            inline = d.get("inlineScanEvaluationCriteriaDetails")
            if not isinstance(inline, dict):
                continue
            inline = strip_typename(inline)
            out_details.append({"inlineScanEvaluationCriteriaDetails": prune_nones(inline)})

    return {"scanEvaluationCriteriaDetails": out_details}

def normalize_schedule_job_configuration(cfg: AppConfig, sjc: Dict[str, Any]) -> Dict[str, Any]:
    sjc = strip_typename(sjc or {})
    out: Dict[str, Any] = {
        "status": sjc.get("status"),
        "name": sjc.get("name") or "",
        "runnerIds": sjc.get("runnerIds") if isinstance(sjc.get("runnerIds"), list) else [],
        "runnerLabels": sjc.get("runnerLabels") if isinstance(sjc.get("runnerLabels"), list) else [],
    }

    daily = sjc.get("dailySchedule")
    weekly = sjc.get("weeklySchedule")
    monthly = sjc.get("monthlySchedule")

    if isinstance(daily, dict) and daily.get("scheduledTime"):
        out["dailySchedule"] = {"scheduledTime": normalize_scheduled_time(daily.get("scheduledTime"))}

    if isinstance(weekly, dict) and weekly.get("scheduledTime"):
        w = {
            "scheduledTime": normalize_scheduled_time(weekly.get("scheduledTime")),
            "scheduledDays": weekly.get("scheduledDays"),
        }
        out["weeklySchedule"] = prune_nones(w)

    if isinstance(monthly, dict) and monthly.get("scheduledTime"):
        msd = monthly.get("scheduledMonthDays") or {}
        msd_out = None
        if isinstance(msd, dict):
            msd_out = {"scheduledDayNumbers": msd.get("scheduledDayNumbers")}
        m = {
            "scheduledTime": normalize_scheduled_time(monthly.get("scheduledTime")),
            "scheduledMonthDays": prune_nones(msd_out) if msd_out else None,
        }
        out["monthlySchedule"] = prune_nones(m)

    # ✅ Optional override: runnerLabels from config
    if cfg.runner_labels is not None:
        out["runnerLabels"] = cfg.runner_labels

    return prune_nones(out)

def normalize_advance_configuration(cfg: AppConfig, adv: Dict[str, Any]) -> Dict[str, Any]:
    adv = strip_typename(adv or {})
    adv["idleTimeoutDuration"] = cfg.new_idle_timeout
    adv["scanTimeoutDuration"] = cfg.new_scan_timeout
    return prune_nones(adv)

# -------------------------------------------------------------------------------------------------
# Introspection: detect update input type for updateScanSuite(update:)
# -------------------------------------------------------------------------------------------------
def unwrap_named_type(t: dict) -> str:
    cur = t
    while cur:
        if cur.get("name"):
            return cur["name"]
        cur = cur.get("ofType")
    raise RuntimeError(f"Could not unwrap named type from: {t}")


def detect_update_scan_suite_input_type(public_client: GraphQLClient) -> str:
    return _detect_mutation_input_type(public_client, "updateScanSuite", "update")


def detect_create_scan_suite_input_type(public_client: GraphQLClient) -> str:
    return _detect_mutation_input_type(public_client, "createScanSuite", "create")


def _detect_mutation_input_type(public_client: GraphQLClient, mutation_name: str, arg_name: str) -> str:
    payload = public_client.execute(GraphQLRequest(query=INTROSPECT_UPDATE_INPUT_TYPE, variables={}))
    fields = (((payload.get("data") or {}).get("__schema") or {}).get("mutationType") or {}).get("fields") or []
    for f in fields:
        if f.get("name") != mutation_name:
            continue
        for a in (f.get("args") or []):
            if a.get("name") == arg_name:
                return unwrap_named_type(a.get("type") or {})
    raise RuntimeError(f"Could not detect {mutation_name}({arg_name}:) input type via introspection.")


# -------------------------------------------------------------------------------------------------
# Failure recording
# -------------------------------------------------------------------------------------------------
def _extract_graphql_error_id(err: Any) -> Optional[str]:
    try:
        if isinstance(err, dict):
            ext = err.get("extensions") or {}
            return ext.get("id")
    except Exception:
        pass
    return None


def record_failure(cfg: AppConfig, suite_id: str, stage: str, error: Exception, payload: Optional[Dict[str, Any]] = None) -> None:
    rec: Dict[str, Any] = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "suite_id": suite_id,
        "stage": stage,
        "error_type": type(error).__name__,
        "error": str(error),
    }

    if payload and isinstance(payload, dict):
        rec["payload"] = payload

    try:
        if isinstance(payload, dict) and "errors" in payload and isinstance(payload["errors"], list):
            rec["graphql_error_ids"] = list(filter(None, (_extract_graphql_error_id(e) for e in payload["errors"])))
    except Exception:
        pass

    with open(cfg.failed_out, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# -------------------------------------------------------------------------------------------------
# Extractors
# -------------------------------------------------------------------------------------------------
def extract_suite_rows_from_query1(payload: Dict[str, Any]) -> List[Tuple[str, str]]:
    data = payload.get("data") or {}
    sa = data.get("searchAst") or {}
    results = sa.get("results") or []
    rows: List[Tuple[str, str]] = []
    for r in results:
        try:
            sid = r["SCAN_SUITE_ID"]["value"]
            sname = (r.get("SCAN_SUITE_NAME") or {}).get("value") or ""
            if sid:
                rows.append((sid, sname))
        except Exception:
            continue
    return rows


def extract_scan_suite_from_query2(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = payload.get("data") or {}
    ss = data.get("scanSuites") or {}
    results = ss.get("results") or []
    if not results:
        raise RuntimeError("No scanSuites results returned for that suiteId.")
    suite = results[0].get("scanSuite")
    if not isinstance(suite, dict):
        raise RuntimeError("scanSuite missing in scanSuites.results[0].")
    return suite


# -------------------------------------------------------------------------------------------------
# Orchestration
# -------------------------------------------------------------------------------------------------
def build_query1(cfg: AppConfig) -> str:
    if cfg.scan_suite_name_like:
        like = gql_escape_string(cfg.scan_suite_name_like)
        # NOTE: value must be a GraphQL literal, not a $variable, because schema expects Unknown!/JSON-ish scalar
        name_filter_line = f'{{ key: SCAN_SUITE_NAME, operator: LIKE, value: "{like}" }}'
    else:
        name_filter_line = ""
    return QUERY1_SEARCH_AST_TEMPLATE.replace("__NAME_LIKE_FILTER__", name_filter_line)



def list_all_suite_ids(cfg: AppConfig, public_client: GraphQLClient, *, limit: int = 500) -> List[Tuple[str, str]]:
    offset = 0
    seen = set()
    all_rows: List[Tuple[str, str]] = []

    q1 = build_query1(cfg)

    regex: Optional[re.Pattern[str]] = None
    if cfg.scan_suite_name_regex:
        regex = re.compile(cfg.scan_suite_name_regex, re.IGNORECASE)

    while True:
        variables = {"limit": limit, "offset": offset}
        payload = public_client.execute(GraphQLRequest(query=q1, variables=variables))

        rows = extract_suite_rows_from_query1(payload)
        if not rows:
            break

        for sid, sname in rows:
            if sid in seen:
                continue

            # Optional local regex filtering on suite name
            if regex is not None and not regex.search(sname or ""):
                continue

            seen.add(sid)
            all_rows.append((sid, sname))

        if len(rows) < limit:
            break
        offset += limit

    return all_rows


def fetch_suite_detail(private_client: GraphQLClient, suite_id: str) -> Dict[str, Any]:
    q = QUERY2_SCAN_SUITES_TEMPLATE.format(suite_id=suite_id.replace('"', '\\"'))
    payload = private_client.execute(GraphQLRequest(query=q, variables={}))
    return extract_scan_suite_from_query2(payload)


def build_full_update_object_from_suite(cfg: AppConfig, suite: Dict[str, Any]) -> Dict[str, Any]:
    suite = strip_typename(suite)

    update_obj: Dict[str, Any] = {
        "id": suite.get("id"),
        "name": suite.get("name"),
        "description": suite.get("description") or "",
        "configuration": normalize_configuration(cfg, suite.get("configuration") or {}),
        "advanceConfiguration": normalize_advance_configuration(cfg, suite.get("advanceConfiguration") or {}),
        "hookConfiguration": normalize_hook_configuration(suite.get("hookConfiguration") or {}),
        "integrationDetails": [],
        "scanEvaluationCriteriaConfiguration": normalize_scan_eval_criteria(suite.get("scanEvaluationCriteriaConfiguration") or {}),
        "scheduleJobConfiguration": normalize_schedule_job_configuration(cfg, suite.get("scheduleJobConfiguration") or {}),
    }

    if not update_obj.get("id"):
        raise RuntimeError("Missing suite.id from Query 2 response; cannot update.")
    if not update_obj.get("name"):
        raise RuntimeError("Missing suite.name from Query 2 response; cannot update.")

    return prune_nones(update_obj)


def build_update_mutation(update_input_type: str) -> str:
    return f"""
mutation UpdateScanSuite($update: {update_input_type}!) {{
  updateScanSuite(update: $update) {{
    success
    __typename
  }}
}}
""".strip()


# -------------------------------------------------------------------------------------------------
# Migration + Gap-Analysis: helpers
# -------------------------------------------------------------------------------------------------

# Owner ID convention seen in suite names like "AD00007290_Daily_Passive_Scan".
# Used as a *fallback* when we can't extract the owner from the asset filter.
_OWNER_ID_RE = re.compile(r"\b(AD\d{6,10})\b", re.IGNORECASE)


def extract_owner_id_from_suite_detail(suite: Dict[str, Any]) -> Optional[str]:
    """Pull the first owner ID from configuration.assetSelections[*].selectedAssetFilter[*].

    The filter we look for has keyExpression.key == "owner", operator == "IN", value=[ID,...].
    Returns the first ID string, or None if nothing usable found.
    """
    if not isinstance(suite, dict):
        return None
    cfg_block = (suite.get("configuration") or {})
    asset_sels = cfg_block.get("assetSelections") or []
    for sel in asset_sels:
        if not isinstance(sel, dict):
            continue
        for f in (sel.get("selectedAssetFilter") or []):
            if not isinstance(f, dict):
                continue
            ke = f.get("keyOrExpression") or f.get("keyExpression") or {}
            if isinstance(ke, dict) and ke.get("key") == "owner":
                val = f.get("value")
                if isinstance(val, list) and val:
                    return str(val[0])
                if isinstance(val, str) and val:
                    return val
    return None


def extract_owner_id_from_name(name: Optional[str]) -> Optional[str]:
    """Fallback: parse owner ID like 'AD00007290' out of a suite name."""
    if not name:
        return None
    m = _OWNER_ID_RE.search(name)
    return m.group(1).upper() if m else None


def build_scans_by_env_query(envs: List[str], name_like: Optional[str]) -> str:
    env_list_literal = json.dumps(envs)  # produces ["akamai-poc"] etc.
    if name_like:
        like = gql_escape_string(name_like)
        name_filter_line = f'{{ key: SCAN_SUITE_NAME, operator: LIKE, value: "{like}" }}'
    else:
        name_filter_line = ""
    return (
        QUERY_SCANS_BY_ENV_TEMPLATE
        .replace("__ENV_LIST__", env_list_literal)
        .replace("__NAME_LIKE_FILTER__", name_filter_line)
    )


def list_suite_rows_by_env(
    cfg: AppConfig,
    public_client: GraphQLClient,
    envs: List[str],
    *,
    name_like: Optional[str] = None,
    limit: int = 500,
) -> List[Tuple[str, str, str]]:
    """Page through searchAst filtered by ENVIRONMENT. Returns (suite_id, suite_name, env)."""
    query = build_scans_by_env_query(envs, name_like)
    offset = 0
    seen: Set[str] = set()
    rows: List[Tuple[str, str, str]] = []
    while True:
        payload = public_client.execute(GraphQLRequest(query=query, variables={"limit": limit, "offset": offset}))
        results = (((payload.get("data") or {}).get("searchAst") or {}).get("results") or [])
        if not results:
            break
        for r in results:
            try:
                sid = (r.get("SCAN_SUITE_ID") or {}).get("value")
                sname = (r.get("SCAN_SUITE_NAME") or {}).get("value") or ""
                senv = (r.get("ENVIRONMENT") or {}).get("value") or ""
                if sid and sid not in seen:
                    seen.add(sid)
                    rows.append((sid, sname, senv))
            except Exception:
                continue
        if len(results) < limit:
            break
        offset += limit
    return rows


def _fetch_one_batch(private_client: GraphQLClient, suite_ids: List[str]) -> List[Dict[str, Any]]:
    """Issue a single batched scanSuites query and return the (cleaned) suite list.
    Raises FatalGraphQLError on schema/server-side errors, caller decides how to recover."""
    ids_literal = json.dumps(suite_ids)
    query = QUERY_SCAN_SUITES_DETAILS_BATCH_TEMPLATE.replace("__SUITE_IDS_LIST__", ids_literal)
    payload = private_client.execute(GraphQLRequest(query=query, variables={}))
    results = (((payload.get("data") or {}).get("scanSuites") or {}).get("results") or [])
    out: List[Dict[str, Any]] = []
    for r in results:
        suite = (r or {}).get("scanSuite")
        if isinstance(suite, dict):
            out.append(strip_typename(suite))
    return out


def fetch_suite_details_batch(
    private_client: GraphQLClient,
    suite_ids: List[str],
    *,
    batch_size: int = 50,
) -> List[Dict[str, Any]]:
    """Fetch slim suite details for a list of suite_ids using IN-list batches.

    Defensive recovery: if a batch fails with FatalGraphQLError (e.g. schema-level
    NullValueInNonNullableField caused by a single legacy suite with dirty data),
    we recursively split the failing batch in half until we isolate the bad suite.
    A single-suite batch that still fails is logged and skipped, so one bad record
    never prevents the rest of the migration from proceeding.
    """
    out: List[Dict[str, Any]] = []
    skipped: List[str] = []

    def _attempt(chunk: List[str]) -> None:
        if not chunk:
            return
        try:
            out.extend(_fetch_one_batch(private_client, chunk))
        except FatalGraphQLError as e:
            if len(chunk) == 1:
                bad_id = chunk[0]
                skipped.append(bad_id)
                logging.warning(
                    "fetch_suite_details_batch: skipping suite_id=%s due to schema error: %s",
                    bad_id, str(e)[:240],
                )
                return
            mid = len(chunk) // 2
            logging.warning(
                "fetch_suite_details_batch: batch of %d failed schema-side, splitting in half (%d / %d)",
                len(chunk), mid, len(chunk) - mid,
            )
            _attempt(chunk[:mid])
            _attempt(chunk[mid:])

    for i in range(0, len(suite_ids), batch_size):
        _attempt(suite_ids[i : i + batch_size])

    if skipped:
        logging.warning(
            "fetch_suite_details_batch: %d suite(s) skipped due to schema-level errors. "
            "These will appear in the report's 'unresolved' list. IDs (first 20): %s",
            len(skipped), skipped[:20],
        )
    return out


def build_owner_index(suite_details: List[Dict[str, Any]]) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """From a list of suite detail dicts, build:
        owner_id -> [ {id, name, environment}, ...  ]
       and a list of suites where owner could not be extracted.
    """
    by_owner: Dict[str, List[Dict[str, Any]]] = {}
    unresolved: List[Dict[str, Any]] = []
    for s in suite_details:
        sid = s.get("id")
        sname = s.get("name") or ""
        senv = s.get("environment") or ""
        owner = extract_owner_id_from_suite_detail(s) or extract_owner_id_from_name(sname)
        record = {"suite_id": sid, "name": sname, "environment": senv}
        if owner:
            by_owner.setdefault(owner, []).append(record)
        else:
            unresolved.append(record)
    return by_owner, unresolved


# ----- create / delete builders ---------------------------------------------------------------

def build_new_suite_name(owner_id: str, target_env: str, suffix: str) -> str:
    """e.g. AD00006850 + f5-mirroring + Daily_Passive_Scan -> AD00006850_f5-mirroring_Daily_Passive_Scan."""
    return f"{owner_id}_{target_env}_{suffix}"


def build_create_scan_suite_input(mig: MigrationConfig, owner_id: str, target_env: str, scan_name: str) -> Dict[str, Any]:
    """Mirrors the user-supplied createScanSuite mutation. Only owner_id, scan_name, target_env vary."""
    return {
        "name": scan_name,
        "description": "",
        "environment": target_env,
        "configuration": {
            "assetSelections": [
                {
                    "selectionMode": "INCLUDE",
                    "selectedAsset": "FILTER_RULE",
                    "selectedAssetFilter": [
                        {
                            "keyExpression": {"key": "isLearnt"},
                            "operator": "EQUALS",
                            "value": True,
                            "type": "ATTRIBUTE",
                        },
                        {
                            "keyExpression": {"key": "owner"},
                            "operator": "IN",
                            "value": [owner_id],
                            "type": "ATTRIBUTE",
                        },
                    ],
                }
            ],
            "policyId": mig.policy_id,
            "targetUrl": "",
            "trafficConfiguration": {"generationTrafficType": "REPLAY_TRAFFIC"},
            "trafficEnvironment": target_env,
            "spanFilters": {"conditions": []},
        },
        "advanceConfiguration": {
            "delayDurationBetweenRequests": mig.delay_duration,
            "idleTimeoutDuration": mig.idle_timeout,
            "scanTimeoutDuration": mig.scan_timeout,
            "totalTestExecutionThreads": mig.test_threads,
        },
        "hookConfiguration": {
            "hookDetails": [{"hookId": mig.hook_id}]
        },
        "integrationDetails": [],
        "scanEvaluationCriteriaConfiguration": {
            "scanEvaluationCriteriaDetails": [
                {
                    "inlineScanEvaluationCriteriaDetails": {
                        "expression": {"allEvaluateTrue": False},
                        "rules": [
                            {
                                "assetScope": {
                                    "assetType": "ENDPOINT",
                                    "assetSelection": {
                                        "selectAllAssets": {"isEnabled": True}
                                    },
                                },
                                "vulnerabilityScopeAndEvaluation": {
                                    "operator": "GREATER_THAN",
                                    "severity": mig.vuln_severity,
                                    "threshold": mig.vuln_threshold,
                                    "vulnerabilitySelection": {
                                        "selectAnyVulnerability": {"isEnabled": True}
                                    },
                                    "vulnerabilityDurationScope": {
                                        "maximumVulnerabilityDuration": {
                                            "vulnerabilityOpenDuration": mig.vuln_open_duration
                                        }
                                    },
                                },
                            }
                        ],
                    }
                }
            ]
        },
        "scheduleJobConfiguration": {
            "status": "ENABLED",
            "name": "",
            "runnerIds": [],
            "runnerLabels": list(mig.runner_labels),
            "dailySchedule": {"scheduledTime": mig.schedule_time},
        },
    }


def build_create_mutation(input_type: str) -> str:
    return CREATE_SUITE_MUTATION_TEMPLATE.replace("__CREATE_INPUT_TYPE__", input_type).strip()


def build_delete_suites_mutation(suite_ids: List[str]) -> str:
    """Inline literal IDs because the schema's list element type for scanSuiteIdList
    is uncertain across deployments. Matches the user-supplied reference mutation."""
    ids_literal = json.dumps(suite_ids)
    return (
        "mutation {\n"
        f"  deleteScanSuites(scanSuiteIdList: {ids_literal}) {{\n"
        "    success\n"
        "    __typename\n"
        "  }\n"
        "}\n"
    )


# ----- explore: list owners (Functionality 2) -------------------------------------------------

def _iso_utc(dt: datetime) -> str:
    """ISO-8601 with millisecond precision and Z suffix, e.g. 2026-05-07T17:03:02.606Z."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def build_explore_owners_query(
    start_time_iso: str,
    end_time_iso: str,
    discovery_states: List[str],
    explore_limit: int,
    group_limit: int,
    offset: int,
) -> str:
    states_literal = json.dumps(discovery_states)
    return f"""
{{
  explore(
    scope: "API"
    limit: {int(explore_limit)}
    between: {{
      startTime: "{start_time_iso}"
      endTime: "{end_time_iso}"
    }}
    offset: {int(offset)}
    filterBy: [
      {{ keyExpression: {{ key: "isLearnt" }}, operator: EQUALS, value: true, type: ATTRIBUTE }}
      {{ keyExpression: {{ key: "owner" }}, operator: NOT_EQUALS, value: "null", type: ATTRIBUTE }}
      {{ keyExpression: {{ key: "apiDiscoveryState" }}, operator: IN, value: {states_literal}, type: ATTRIBUTE }}
    ]
    groupBy: {{
      expressions: [{{ key: "owner" }}]
      groupLimit: {int(group_limit)}
      includeRest: false
    }}
    orderBy: [
      {{ aggregation: DISTINCTCOUNT, direction: DESC, keyExpression: {{ key: "id" }} }}
    ]
    entityContextOptions: {{ includeNonLiveEntities: true }}
  ) {{
    results {{
      owner: selection(expression: {{ key: "owner" }}) {{ value type __typename }}
      distinct_count_id: selection(expression: {{ key: "id" }}, aggregation: DISTINCTCOUNT) {{ value type __typename }}
      __typename
    }}
    total
    __typename
  }}
}}
""".strip()


def list_all_owners(cfg: AppConfig, gap: GapAnalysisConfig, private_client: GraphQLClient) -> List[Dict[str, Any]]:
    """Run the explore query and return [{owner_id, distinct_count_id}, ...]."""
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(hours=gap.owner_window_hours)
    query = build_explore_owners_query(
        start_time_iso=_iso_utc(start_dt),
        end_time_iso=_iso_utc(end_dt),
        discovery_states=gap.discovery_states,
        explore_limit=gap.explore_limit,
        group_limit=gap.group_limit,
        offset=0,
    )
    payload = private_client.execute(GraphQLRequest(query=query, variables={}))
    results = (((payload.get("data") or {}).get("explore") or {}).get("results") or [])
    out: List[Dict[str, Any]] = []
    for r in results:
        try:
            owner_id = (r.get("owner") or {}).get("value")
            count = (r.get("distinct_count_id") or {}).get("value")
            if owner_id and isinstance(owner_id, str) and owner_id.lower() != "null":
                out.append({"owner_id": owner_id, "distinct_count_id": count})
        except Exception:
            continue
    return out


# -------------------------------------------------------------------------------------------------
# Migration + Gap-Analysis: create/delete execution
# -------------------------------------------------------------------------------------------------

def execute_create_for_owners(
    cfg: AppConfig,
    mig: MigrationConfig,
    public_client: GraphQLClient,
    target_env: str,
    owners: List[str],
    *,
    dry_run: bool,
    label: str,
) -> Dict[str, Any]:
    """For each owner ID, build a createScanSuite payload and (unless dry-run) execute it.
    Returns a summary dict suitable for embedding in the JSON report.
    """
    planned: List[Dict[str, Any]] = []
    created: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []

    if not owners:
        logging.info("[%s] No owners need a new suite. Nothing to create.", label)
        return {"planned": planned, "created": created, "failed": failed}

    create_input_type = "CreateScanSuiteInput"
    if not dry_run:
        try:
            create_input_type = detect_create_scan_suite_input_type(public_client)
            logging.info("[%s] Detected createScanSuite(create:) input type = %s", label, create_input_type)
        except Exception as e:
            logging.warning("[%s] Falling back to default createScanSuite input type %r (%s).",
                            label, create_input_type, e)

    mutation = build_create_mutation(create_input_type)

    total = len(owners)
    for i, owner_id in enumerate(owners, start=1):
        scan_name = build_new_suite_name(owner_id, target_env, mig.scan_name_suffix)
        create_input = build_create_scan_suite_input(mig, owner_id, target_env, scan_name)
        variables = {"create": create_input}
        plan_record = {
            "owner_id": owner_id,
            "new_suite_name": scan_name,
            "target_env": target_env,
        }
        planned.append(plan_record)

        if dry_run:
            logging.info("[%s] (DRY) (%d/%d) would create suite %s for owner=%s",
                         label, i, total, scan_name, owner_id)
            dump_request_artifacts(cfg, f"create_{owner_id}", mutation, variables)
            continue

        try:
            print_request_artifacts(cfg, mutation, variables)
            dump_request_artifacts(cfg, f"create_{owner_id}", mutation, variables)
            payload = public_client.execute(GraphQLRequest(query=mutation, variables=variables))
            new_id = (((payload.get("data") or {}).get("createScanSuite") or {}).get("id"))
            if new_id:
                created.append({**plan_record, "new_suite_id": new_id})
                logging.info("[%s] ✅ (%d/%d) created suite_id=%s for owner=%s",
                             label, i, total, new_id, owner_id)
            else:
                failed.append({**plan_record, "error": "createScanSuite returned no id", "payload": payload})
                logging.error("[%s] ❌ (%d/%d) create returned no id for owner=%s. payload=%s",
                              label, i, total, owner_id, json.dumps(payload)[:600])
                dump_failure_artifacts(cfg, f"create_{owner_id}", mutation, variables, payload)
                record_failure(cfg, suite_id=f"create_{owner_id}", stage="create_no_id",
                               error=RuntimeError("createScanSuite returned no id"), payload=payload)
        except Exception as e:
            failed.append({**plan_record, "error": str(e), "error_type": type(e).__name__})
            logging.exception("[%s] ❌ (%d/%d) create failed for owner=%s: %s",
                              label, i, total, owner_id, e)
            dump_failure_artifacts(cfg, f"create_{owner_id}", mutation, variables, {"error": str(e)})
            record_failure(cfg, suite_id=f"create_{owner_id}", stage="create_exception", error=e)

    return {"planned": planned, "created": created, "failed": failed}


def execute_delete_suites(
    cfg: AppConfig,
    public_client: GraphQLClient,
    suite_ids: List[str],
    *,
    dry_run: bool,
    label: str = "delete",
) -> Dict[str, Any]:
    """Delete scan suites by ID. Returns a summary."""
    if not suite_ids:
        logging.info("[%s] No suite IDs to delete.", label)
        return {"requested": [], "success": False, "dry_run": dry_run}

    mutation = build_delete_suites_mutation(suite_ids)
    if dry_run:
        logging.info("[%s] (DRY) would delete %d suites: %s", label, len(suite_ids), suite_ids[:10])
        dump_text(cfg.debug_dump_dir / f"DRY_delete_{int(time.time())}.graphql", mutation)
        return {"requested": suite_ids, "success": None, "dry_run": True}

    print_request_artifacts(cfg, mutation, {"scanSuiteIdList": suite_ids})
    dump_text(cfg.debug_dump_dir / f"delete_{int(time.time())}.graphql", mutation)
    try:
        payload = public_client.execute(GraphQLRequest(query=mutation, variables={}))
        success = bool(((payload.get("data") or {}).get("deleteScanSuites") or {}).get("success"))
        if success:
            logging.info("[%s] ✅ deleted %d suites.", label, len(suite_ids))
        else:
            logging.error("[%s] ❌ deleteScanSuites returned success=false. payload=%s",
                          label, json.dumps(payload)[:600])
            dump_failure_artifacts(cfg, f"delete_{int(time.time())}", mutation, {}, payload)
            record_failure(cfg, suite_id=",".join(suite_ids[:5]), stage="delete_success_false",
                           error=RuntimeError("deleteScanSuites success=false"), payload=payload)
        return {"requested": suite_ids, "success": success, "dry_run": False, "payload": payload}
    except Exception as e:
        logging.exception("[%s] ❌ delete failed: %s", label, e)
        dump_failure_artifacts(cfg, f"delete_{int(time.time())}", mutation, {}, {"error": str(e)})
        record_failure(cfg, suite_id=",".join(suite_ids[:5]), stage="delete_exception", error=e)
        return {"requested": suite_ids, "success": False, "dry_run": False, "error": str(e)}


# -------------------------------------------------------------------------------------------------
# Migration + Gap-Analysis: command handlers
# -------------------------------------------------------------------------------------------------

def cmd_migrate(cfg: AppConfig, public_client: GraphQLClient, private_client: GraphQLClient) -> Dict[str, Any]:
    """Functionality 1: migrate suites from source_env to target_env (template create only).
    Returns the report dict (also written to disk per cfg.migration.report_out).
    """
    if cfg.migration is None:
        raise RuntimeError("config.migration is missing. Add a 'migration' section in config.json to use this subcommand.")

    mig = cfg.migration
    logging.info("=== migrate: source=%s -> target=%s (dry_run=%s) ===",
                 mig.source_env, mig.target_env, cfg.dry_run)

    # 1) List suites in source_env and target_env (env-filtered).
    source_rows = list_suite_rows_by_env(cfg, public_client, [mig.source_env], limit=500)
    target_rows = list_suite_rows_by_env(cfg, public_client, [mig.target_env], limit=500)
    logging.info("source_env=%s suites=%d | target_env=%s suites=%d",
                 mig.source_env, len(source_rows), mig.target_env, len(target_rows))

    # 2) Fetch slim details for both, batched, to extract owner IDs.
    source_details = fetch_suite_details_batch(
        private_client, [sid for sid, _, _ in source_rows], batch_size=mig.batch_size
    )
    target_details = fetch_suite_details_batch(
        private_client, [sid for sid, _, _ in target_rows], batch_size=mig.batch_size
    )

    source_by_owner, source_unresolved = build_owner_index(source_details)
    target_by_owner, _target_unresolved = build_owner_index(target_details)

    # 3) Diff on owner ID only (per user's preference).
    owners_in_source = set(source_by_owner.keys())
    owners_in_target = set(target_by_owner.keys())
    owners_to_migrate_set = owners_in_source - owners_in_target
    owners_already = owners_in_source & owners_in_target

    # Stable order for the report
    owners_to_migrate = sorted(owners_to_migrate_set)

    # Build the per-owner planned-changes table for the report
    planned_table: List[Dict[str, Any]] = []
    for owner in owners_to_migrate:
        source_records = source_by_owner.get(owner, [])
        planned_table.append({
            "owner_id": owner,
            "source_suite_ids": [r["suite_id"] for r in source_records],
            "source_suite_names": [r["name"] for r in source_records],
            "new_suite_name": build_new_suite_name(owner, mig.target_env, mig.scan_name_suffix),
        })

    # 4) Execute (or dry-run) the creates.
    create_summary = execute_create_for_owners(
        cfg, mig, public_client,
        target_env=mig.target_env,
        owners=owners_to_migrate,
        dry_run=cfg.dry_run,
        label="migrate",
    )

    # 5) Compose + write the report.
    report = {
        "mode": "migrate",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": cfg.dry_run,
        "source_env": mig.source_env,
        "target_env": mig.target_env,
        "source_suite_count": len(source_rows),
        "target_suite_count": len(target_rows),
        "source_owner_count": len(owners_in_source),
        "target_owner_count": len(owners_in_target),
        "owners_in_source": sorted(owners_in_source),
        "owners_in_target": sorted(owners_in_target),
        "owners_to_migrate": owners_to_migrate,
        "owners_already_in_target": sorted(owners_already),
        "source_suites_with_unresolved_owner": source_unresolved,
        "planned_creates": planned_table,
        "create_summary": create_summary,
    }

    out_path = Path(mig.report_out)
    dump_json(out_path, report)
    logging.info("Migration report written to %s", out_path)
    logging.info("Summary: source_owners=%d target_owners=%d to_migrate=%d already=%d",
                 len(owners_in_source), len(owners_in_target),
                 len(owners_to_migrate), len(owners_already))
    return report


def cmd_gap_analysis(cfg: AppConfig, public_client: GraphQLClient, private_client: GraphQLClient) -> Dict[str, Any]:
    """Functionality 2: find owners with no scan in target_env, optionally create them."""
    if cfg.gap_analysis is None:
        raise RuntimeError("config.gap_analysis is missing. Add a 'gap_analysis' section in config.json to use this subcommand.")
    if cfg.migration is None:
        raise RuntimeError("config.migration is missing. The gap-analysis create flow reuses the migration template.")

    gap = cfg.gap_analysis
    mig = cfg.migration

    logging.info("=== gap-analysis: target_env=%s window_hours=%d (dry_run=%s) ===",
                 gap.target_env, gap.owner_window_hours, cfg.dry_run)

    # 1) Owners discovered in last N hours.
    explore_owners = list_all_owners(cfg, gap, private_client)
    discovered_owner_ids = [o["owner_id"] for o in explore_owners]
    logging.info("Owners discovered via explore (last %dh): %d", gap.owner_window_hours, len(discovered_owner_ids))

    # 2) Existing scan suites in target_env, then extract owners.
    target_rows = list_suite_rows_by_env(cfg, public_client, [gap.target_env], limit=500)
    target_details = fetch_suite_details_batch(
        private_client, [sid for sid, _, _ in target_rows], batch_size=mig.batch_size
    )
    target_by_owner, target_unresolved = build_owner_index(target_details)
    owners_with_scan_in_target = set(target_by_owner.keys())
    logging.info("Owners with at least one scan in target_env=%s: %d",
                 gap.target_env, len(owners_with_scan_in_target))

    # 3) Diff: owners discovered but with no scan in target_env.
    gaps_set = set(discovered_owner_ids) - owners_with_scan_in_target
    gaps = sorted(gaps_set)
    logging.info("Gap owners (no scan in target_env): %d", len(gaps))

    # 4) Execute (or dry-run) the creates.
    create_summary = execute_create_for_owners(
        cfg, mig, public_client,
        target_env=gap.target_env,
        owners=gaps,
        dry_run=cfg.dry_run,
        label="gap-analysis",
    )

    # 5) Compose + write the report.
    report = {
        "mode": "gap-analysis",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": cfg.dry_run,
        "target_env": gap.target_env,
        "owner_window_hours": gap.owner_window_hours,
        "discovery_states": gap.discovery_states,
        "owners_discovered_count": len(discovered_owner_ids),
        "owners_with_scan_in_target_count": len(owners_with_scan_in_target),
        "gap_owner_count": len(gaps),
        "owners_discovered": discovered_owner_ids,
        "owners_with_scan_in_target": sorted(owners_with_scan_in_target),
        "gap_owners": gaps,
        "target_suites_with_unresolved_owner": target_unresolved,
        "create_summary": create_summary,
    }

    out_path = Path(gap.report_out)
    dump_json(out_path, report)
    logging.info("Gap-analysis report written to %s", out_path)
    logging.info("Summary: discovered=%d in_target=%d gaps=%d",
                 len(discovered_owner_ids), len(owners_with_scan_in_target), len(gaps))
    return report


def cmd_delete_suites_by_ids(cfg: AppConfig, public_client: GraphQLClient, ids_csv: str) -> Dict[str, Any]:
    """Delete a comma-separated list of suite IDs. Respects cfg.dry_run."""
    suite_ids = [s.strip() for s in (ids_csv or "").split(",") if s.strip()]
    if not suite_ids:
        raise RuntimeError("--ids must be a non-empty comma-separated list of suite IDs.")
    logging.info("=== delete-suites: %d ids (dry_run=%s) ===", len(suite_ids), cfg.dry_run)
    return execute_delete_suites(cfg, public_client, suite_ids, dry_run=cfg.dry_run, label="delete-suites")


def cmd_delete_source_env(cfg: AppConfig, public_client: GraphQLClient, private_client: GraphQLClient) -> Dict[str, Any]:
    """Delete source_env suites that have an owner-counterpart in target_env (safe post-migration cleanup).
    Always validates against the current target_env state -- never deletes a source suite whose owner
    is NOT already represented in target_env.
    """
    if cfg.migration is None:
        raise RuntimeError("config.migration is missing. Required for delete-source.")
    mig = cfg.migration
    logging.info("=== delete-source: source=%s target=%s (dry_run=%s) ===",
                 mig.source_env, mig.target_env, cfg.dry_run)

    source_rows = list_suite_rows_by_env(cfg, public_client, [mig.source_env], limit=500)
    target_rows = list_suite_rows_by_env(cfg, public_client, [mig.target_env], limit=500)

    source_details = fetch_suite_details_batch(
        private_client, [sid for sid, _, _ in source_rows], batch_size=mig.batch_size
    )
    target_details = fetch_suite_details_batch(
        private_client, [sid for sid, _, _ in target_rows], batch_size=mig.batch_size
    )

    source_by_owner, source_unresolved = build_owner_index(source_details)
    target_by_owner, _ = build_owner_index(target_details)

    safe_to_delete: List[str] = []
    skipped: List[Dict[str, Any]] = []
    for owner, recs in source_by_owner.items():
        if owner in target_by_owner:
            for r in recs:
                safe_to_delete.append(r["suite_id"])
        else:
            for r in recs:
                skipped.append({**r, "reason": "no_target_counterpart"})

    if source_unresolved:
        for r in source_unresolved:
            skipped.append({**r, "reason": "owner_not_resolvable"})

    summary = execute_delete_suites(cfg, public_client, safe_to_delete, dry_run=cfg.dry_run, label="delete-source")

    report = {
        "mode": "delete-source",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": cfg.dry_run,
        "source_env": mig.source_env,
        "target_env": mig.target_env,
        "source_suite_count": len(source_rows),
        "target_suite_count": len(target_rows),
        "to_delete_count": len(safe_to_delete),
        "to_delete_ids": safe_to_delete,
        "skipped": skipped,
        "delete_result": summary,
    }
    report_path = Path("delete_source_report.json")
    dump_json(report_path, report)
    logging.info("delete-source report written to %s", report_path)
    return report


# -------------------------------------------------------------------------------------------------
# Update flow (existing): extracted into a callable so subparser can dispatch to it
# -------------------------------------------------------------------------------------------------
def cmd_update(cfg: AppConfig, public_client: GraphQLClient, private_client: GraphQLClient) -> None:
    update_input_type = detect_update_scan_suite_input_type(public_client)
    logging.info("Detected updateScanSuite(update:) input type = %s", update_input_type)

    suite_rows = list_all_suite_ids(cfg, public_client, limit=500)
    logging.info("Found %d unique scan suite IDs after filters (LIKE=%s, REGEX=%s)",
                 len(suite_rows), cfg.scan_suite_name_like, cfg.scan_suite_name_regex)

    if not suite_rows:
        return

    effective_rows = suite_rows
    if cfg.dry_run and cfg.dry_run_max_suites is not None:
        effective_rows = suite_rows[: cfg.dry_run_max_suites]
        logging.info("DRY_RUN enabled: limiting to first %d suites", len(effective_rows))

    updated = 0
    failed = 0
    total = len(effective_rows)

    mutation = build_update_mutation(update_input_type)

    for i, (suite_id, suite_name_from_q1) in enumerate(effective_rows, start=1):
        logging.info("(%d/%d) Processing suite_id=%s name_from_q1=%s", i, total, suite_id, suite_name_from_q1)

        last_variables: Dict[str, Any] = {}
        last_payload: Dict[str, Any] = {}

        try:
            suite = fetch_suite_detail(private_client, suite_id)
            suite_name = suite.get("name", suite_name_from_q1) or suite_name_from_q1

            before_adv = strip_typename(suite.get("advanceConfiguration") or {})

            update_obj = build_full_update_object_from_suite(cfg, suite)
            if getattr(cfg, "runner_labels", None) is not None:
                sjc = update_obj.get("scheduleJobConfiguration") or {}
                sjc["runnerLabels"] = list(cfg.runner_labels)
                sjc["runnerIds"] = []
                if not sjc.get("status"):
                    if sjc.get("dailySchedule") or sjc.get("weeklySchedule") or sjc.get("monthlySchedule"):
                        sjc["status"] = "ENABLED"
                update_obj["scheduleJobConfiguration"] = prune_nones(sjc)

            after_adv = update_obj.get("advanceConfiguration") or {}
            last_variables = {"update": update_obj}

            if cfg.dry_run:
                print("\n" + "=" * 120)
                print(f"DRY-RUN ({i}/{total}) suite_id={suite_id} name={suite_name}")
                print("- Before advanceConfiguration:")
                print(json.dumps(before_adv, indent=2))
                print("- After  advanceConfiguration:")
                print(json.dumps(after_adv, indent=2))
                print("- scheduleJobConfiguration.runnerLabels (effective):")
                sjc = (update_obj.get("scheduleJobConfiguration") or {})
                print(json.dumps({"runnerLabels": sjc.get("runnerLabels")}, indent=2))
                print("=" * 120)

                dump_request_artifacts(cfg, suite_id, mutation, last_variables)
                continue

            print_request_artifacts(cfg, mutation, last_variables)
            dump_request_artifacts(cfg, suite_id, mutation, last_variables)

            last_payload = public_client.execute(GraphQLRequest(query=mutation, variables=last_variables))
            success = bool(((last_payload.get("data") or {}).get("updateScanSuite") or {}).get("success"))

            if not success:
                failed += 1
                logging.error("Update returned success=false for suite_id=%s (name=%s). Continuing.",
                              suite_id, suite_name)
                dump_failure_artifacts(cfg, suite_id, mutation, last_variables, last_payload)
                record_failure(
                    cfg, suite_id=suite_id,
                    stage="update_success_false",
                    error=RuntimeError("updateScanSuite returned success=false"),
                    payload=last_payload,
                )
                continue

            updated += 1
            logging.info("✅ Updated suite_id=%s (idle=%s, scan=%s, runnerLabels=%s)",
                         suite_id, cfg.new_idle_timeout, cfg.new_scan_timeout,
                         (update_obj.get("scheduleJobConfiguration") or {}).get("runnerLabels"))

        except FatalGraphQLError as e:
            failed += 1
            logging.error("❌ FatalGraphQLError for suite_id=%s: %s (continuing)", suite_id, e)
            dump_failure_artifacts(cfg, suite_id, mutation, last_variables, {"error": str(e)})
            record_failure(cfg, suite_id=suite_id, stage="fatal_graphql_error", error=e, payload={"error": str(e)})
            continue

        except Exception as e:
            failed += 1
            logging.exception("❌ Error for suite_id=%s: %s (continuing)", suite_id, e)
            dump_failure_artifacts(cfg, suite_id, mutation, last_variables, last_payload or {"error": str(e)})
            record_failure(cfg, suite_id=suite_id, stage="exception", error=e, payload=last_payload or None)
            continue

    if cfg.dry_run:
        logging.info("DRY_RUN complete. No updates were sent.")
    else:
        logging.info("DONE. Updated=%d Failed=%d Total=%d", updated, failed, total)
        if failed:
            logging.info("Failures written to %s", cfg.failed_out)


# -------------------------------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------------------------------
def run() -> None:
    # Two parent parsers so --dry-run / --apply work both BEFORE and AFTER the subcommand.
    # The subparser version uses SUPPRESS as its default so it doesn't clobber a value the
    # top-level parser already set (e.g. `python main.py --dry-run migrate`).
    top_common = argparse.ArgumentParser(add_help=False)
    top_common.add_argument("--dry-run", action="store_true", default=False,
                            help="Force dry-run (overrides config.dry_run.enabled)")
    top_common.add_argument("--apply", action="store_true", default=False,
                            help="Force apply (overrides config.dry_run.enabled). Wins over --dry-run.")

    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS,
                            help="Force dry-run (overrides config.dry_run.enabled)")
    sub_common.add_argument("--apply", action="store_true", default=argparse.SUPPRESS,
                            help="Force apply (overrides config.dry_run.enabled). Wins over --dry-run.")

    parser = argparse.ArgumentParser(
        description="Traceable scan-suite admin CLI (update / migrate / gap-analysis / delete).",
        parents=[top_common],
    )
    parser.add_argument("--config", default="config.json", help="Path to config.json")

    subparsers = parser.add_subparsers(dest="cmd")

    subparsers.add_parser("update", parents=[sub_common],
                          help="Bulk update scan-suite timeouts/runners (existing behavior).")
    subparsers.add_parser("migrate", parents=[sub_common],
                          help="Functionality 1: migrate suites from source_env to target_env.")
    subparsers.add_parser("gap-analysis", parents=[sub_common],
                          help="Functionality 2: find owners with no scan in target_env.")

    p_del = subparsers.add_parser("delete-suites", parents=[sub_common],
                                  help="Delete scan suites by ID list.")
    p_del.add_argument("--ids", required=True,
                       help="Comma-separated scan suite IDs to delete.")

    subparsers.add_parser("delete-source", parents=[sub_common],
                          help="Delete source_env suites whose owner already has a target_env counterpart.")

    args = parser.parse_args()

    cfg = load_config(args.config)

    # CLI override of dry-run (--apply wins over --dry-run wins over config).
    if args.apply:
        cfg.dry_run = False
    elif args.dry_run:
        cfg.dry_run = True

    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(message)s")
    cfg.debug_dump_dir.mkdir(parents=True, exist_ok=True)

    public_auth = f"Bearer {cfg.public_token}" if cfg.public_use_bearer else cfg.public_token
    private_auth = f"Bearer {cfg.private_token}" if cfg.private_use_bearer else cfg.private_token

    public_headers = {"Content-Type": "application/json", "Authorization": public_auth}
    private_headers = {"Content-Type": "application/json", "Authorization": private_auth}

    public_client = GraphQLClient(
        endpoint=cfg.public_gql,
        headers=public_headers,
        min_interval_s=cfg.public_min_interval_s,
        max_retries=cfg.public_max_retries,
    )
    private_client = GraphQLClient(
        endpoint=cfg.private_gql,
        headers=private_headers,
        min_interval_s=cfg.private_min_interval_s,
        max_retries=cfg.private_max_retries,
    )

    cmd = args.cmd or "update"   # backward-compat: no subcommand -> update

    if cmd == "update":
        cmd_update(cfg, public_client, private_client)
    elif cmd == "migrate":
        cmd_migrate(cfg, public_client, private_client)
    elif cmd == "gap-analysis":
        cmd_gap_analysis(cfg, public_client, private_client)
    elif cmd == "delete-suites":
        cmd_delete_suites_by_ids(cfg, public_client, args.ids)
    elif cmd == "delete-source":
        cmd_delete_source_env(cfg, public_client, private_client)
    else:
        raise RuntimeError(f"Unknown subcommand: {cmd}")


if __name__ == "__main__":
    run()
