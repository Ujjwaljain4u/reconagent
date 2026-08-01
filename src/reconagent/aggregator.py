"""
Aggregator: runs every collector registered for the given target_type,
in parallel, with per-collector fault isolation — one collector's crash
or timeout never takes down the whole recon run.
"""

from __future__ import annotations

import concurrent.futures

from reconagent.collectors import collectors_for
from reconagent.models import CollectorResult

DEFAULT_TIMEOUT_S = 30


def run_recon(target: str, target_type: str, timeout_s: int = DEFAULT_TIMEOUT_S) -> list[CollectorResult]:
    collectors = collectors_for(target_type)
    results: list[CollectorResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(collectors))) as pool:
        future_map = {
            pool.submit(_safe_run, c, target, target_type): c for c in collectors
        }
        pending = set(future_map.keys())
        try:
            for future in concurrent.futures.as_completed(future_map, timeout=timeout_s * 2):
                pending.discard(future)
                collector = future_map[future]
                try:
                    results.append(future.result(timeout=timeout_s))
                except concurrent.futures.TimeoutError:
                    results.append(CollectorResult(
                        collector=collector.name, target=target, ok=False,
                        error=f"timed out after {timeout_s}s",
                    ))
                except Exception as e:  # noqa: BLE001 - never let one collector kill the run
                    results.append(CollectorResult(
                        collector=collector.name, target=target, ok=False,
                        error=f"unexpected error: {e}",
                    ))
        except concurrent.futures.TimeoutError:
            # as_completed's own overall-wait budget expired (e.g. a slow collector like
            # crt.sh mid-retry) — mark whatever's still pending as timed out instead of
            # letting the exception propagate and take down the whole request.
            for future in pending:
                collector = future_map[future]
                future.cancel()
                results.append(CollectorResult(
                    collector=collector.name, target=target, ok=False,
                    error=f"timed out after {timeout_s * 2}s (overall sweep budget)",
                ))
    return results


def _safe_run(collector, target: str, target_type: str) -> CollectorResult:
    if not collector.is_configured():
        return CollectorResult(
            collector=collector.name, target=target, ok=False,
            error=f"skipped: requires {collector.key_env_var} env var (not set)",
        )
    return collector.run(target, target_type)