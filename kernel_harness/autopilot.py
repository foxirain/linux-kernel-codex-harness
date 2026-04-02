from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from kernel_harness.ingest import parse_response
from kernel_harness.session import (
    completed_ranks,
    load_state,
    record_review,
    response_archive_dir,
    response_path,
    save_state,
    set_pending_review,
)

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
MAX_MANUAL_FOLLOWUPS = 2
STRONG_FINDING_VERDICTS = {"cve_candidate", "plausible_security_bug"}
AUTOPILOT_DIRNAME = "autopilot"


def run_autopilot(
    session_dir: Path,
    *,
    include_snippet: bool,
    duration_spec: str,
    per_run_timeout_spec: str,
    model: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
    stop_on_finding: bool,
) -> int:
    session_dir = session_dir.expanduser().resolve()
    manifest = _load_manifest(session_dir)
    autopilot_dir = session_dir / AUTOPILOT_DIRNAME
    prompts_dir = autopilot_dir / "prompts"
    exec_dir = autopilot_dir / "exec"
    findings_dir = autopilot_dir / "findings"
    for path in (autopilot_dir, prompts_dir, exec_dir, findings_dir):
        path.mkdir(parents=True, exist_ok=True)

    progress_path = autopilot_dir / "AUTOPILOT_PROGRESS.txt"
    findings_path = autopilot_dir / "AUTOPILOT_FINDINGS.txt"
    status_path = autopilot_dir / "AUTOPILOT_STATUS.txt"

    duration_seconds = _parse_duration(duration_spec)
    per_run_timeout_seconds = _parse_duration(per_run_timeout_spec)
    started_at = datetime.now(UTC)
    deadline = time.monotonic() + duration_seconds
    run_index = _existing_run_count(prompts_dir)

    _append_text(
        progress_path,
        (
            f"\n== AUTOPILOT START {started_at.strftime('%Y-%m-%d %H:%M:%SZ')} ==\n"
            f"session={session_dir}\n"
            f"repo_root={manifest.get('repo_root', '')}\n"
            f"duration={duration_spec}\n"
            f"per_run_timeout={per_run_timeout_spec}\n"
            f"include_snippet={int(include_snippet)}\n"
            f"model={model or '<default>'}\n"
        ),
    )
    _write_status(
        status_path,
        stage="starting",
        session_dir=session_dir,
        repo_root=manifest.get("repo_root", ""),
        started_at=started_at,
        duration_spec=duration_spec,
        runs=run_index,
    )

    while time.monotonic() < deadline:
        result = _ingest_pending_response(session_dir, findings_dir, findings_path, progress_path)
        if result is not None:
            _write_status(
                status_path,
                stage="ingested",
                session_dir=session_dir,
                repo_root=manifest.get("repo_root", ""),
                started_at=started_at,
                duration_spec=duration_spec,
                runs=run_index,
                last_target=result["target"],
                last_verdict=result["verdict"],
                last_next_target=result["next_target"],
            )
            if stop_on_finding and result["verdict"] in STRONG_FINDING_VERDICTS:
                _append_text(progress_path, "stop_reason=strong_finding_detected\n")
                _write_status(
                    status_path,
                    stage="stopped_on_finding",
                    session_dir=session_dir,
                    repo_root=manifest.get("repo_root", ""),
                    started_at=started_at,
                    duration_spec=duration_spec,
                    runs=run_index,
                    last_target=result["target"],
                    last_verdict=result["verdict"],
                    last_next_target=result["next_target"],
                )
                return 0

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        try:
            next_prompt = _render_next_prompt(session_dir, include_snippet=include_snippet)
        except SystemExit as exc:
            _append_text(progress_path, f"stop_reason={str(exc)}\n")
            _write_status(
                status_path,
                stage="finished",
                session_dir=session_dir,
                repo_root=manifest.get("repo_root", ""),
                started_at=started_at,
                duration_spec=duration_spec,
                runs=run_index,
            )
            return 0

        run_index += 1
        prompt_path = prompts_dir / f"run-{run_index:04d}.prompt.txt"
        stdout_path = exec_dir / f"run-{run_index:04d}.stdout.txt"
        stderr_path = exec_dir / f"run-{run_index:04d}.stderr.txt"
        prompt_text = _build_autopilot_prompt(next_prompt)
        prompt_path.write_text(prompt_text, encoding="utf-8")

        _append_text(
            progress_path,
            (
                f"\n== RUN {run_index:04d} {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\n"
                f"rank={next_prompt['rank']}\n"
                f"target={next_prompt['target']}\n"
                f"prompt_source={next_prompt['prompt_source']}\n"
                f"fixed_response_file={response_path(session_dir)}\n"
            ),
        )
        _write_status(
            status_path,
            stage="running",
            session_dir=session_dir,
            repo_root=manifest.get("repo_root", ""),
            started_at=started_at,
            duration_spec=duration_spec,
            runs=run_index,
            current_target=next_prompt["target"],
            current_rank=next_prompt["rank"],
        )

        timeout_seconds = max(1, min(int(remaining), per_run_timeout_seconds))
        proc = _run_codex_exec(
            repo_root=next_prompt["repo_root"],
            prompt_text=prompt_text,
            response_file=response_path(session_dir),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=timeout_seconds,
            model=model,
            sandbox=sandbox,
            full_auto=full_auto,
            unsafe_bypass=unsafe_bypass,
        )

        _append_text(
            progress_path,
            (
                f"codex_exit_code={proc.returncode}\n"
                f"stdout_file={stdout_path}\n"
                f"stderr_file={stderr_path}\n"
            ),
        )
        if proc.returncode != 0 and not _has_nonempty_response(response_path(session_dir)):
            _append_text(progress_path, "stop_reason=codex_exec_failed_without_response\n")
            _write_status(
                status_path,
                stage="failed",
                session_dir=session_dir,
                repo_root=manifest.get("repo_root", ""),
                started_at=started_at,
                duration_spec=duration_spec,
                runs=run_index,
                current_target=next_prompt["target"],
                current_rank=next_prompt["rank"],
            )
            return proc.returncode or 1

    final_result = _ingest_pending_response(session_dir, findings_dir, findings_path, progress_path)
    _write_status(
        status_path,
        stage="finished",
        session_dir=session_dir,
        repo_root=manifest.get("repo_root", ""),
        started_at=started_at,
        duration_spec=duration_spec,
        runs=run_index,
        last_target=(final_result or {}).get("target", ""),
        last_verdict=(final_result or {}).get("verdict", ""),
        last_next_target=(final_result or {}).get("next_target", ""),
    )
    _append_text(progress_path, f"== AUTOPILOT END {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\n")
    return 0


def _run_codex_exec(
    *,
    repo_root: str,
    prompt_text: str,
    response_file: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
    model: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        "codex",
        "exec",
        "-C",
        repo_root,
        "--skip-git-repo-check",
        "--add-dir",
        str(PACKAGE_ROOT),
        "-o",
        str(response_file),
        "--color",
        "never",
    ]
    if unsafe_bypass:
        cmd.append("--dangerously-bypass-approvals-and-sandbox")
    else:
        if full_auto:
            cmd.append("--full-auto")
        cmd.extend(["--sandbox", sandbox])
    if model:
        cmd.extend(["-m", model])

    try:
        proc = subprocess.run(
            cmd,
            input=prompt_text,
            text=True,
            capture_output=True,
            cwd=str(PACKAGE_ROOT),
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_text = _ensure_text(exc.stdout)
        stderr_text = _ensure_text(exc.stderr) + "\nTIMEOUT\n"
        stdout_path.write_text(stdout_text, encoding="utf-8")
        stderr_path.write_text(stderr_text, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 124, stdout_text, stderr_text)

    stdout_path.write_text(proc.stdout or "", encoding="utf-8")
    stderr_path.write_text(proc.stderr or "", encoding="utf-8")
    return proc


def _ingest_pending_response(session_dir: Path, findings_dir: Path, findings_path: Path, progress_path: Path) -> dict | None:
    fixed_response = response_path(session_dir)
    state = load_state(session_dir)
    pending_target = (state.get("pending_target") or "").strip()
    if not pending_target or not fixed_response.exists() or fixed_response.stat().st_size == 0:
        return None

    text = fixed_response.read_text(encoding="utf-8")
    try:
        parsed = parse_response(text)
    except ValueError as exc:
        archive_path = _archive_response_file(session_dir, fixed_response)
        parse_dir = session_dir / AUTOPILOT_DIRNAME / "parse_errors"
        parse_dir.mkdir(parents=True, exist_ok=True)
        parse_path = parse_dir / f"parse-error-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{_slugify(pending_target)[:60]}.txt"
        parse_path.write_text(text, encoding="utf-8")
        updated = record_review(
            session_dir=session_dir,
            rank=state.get("pending_rank"),
            target=pending_target,
            verdict="needs_more_context",
            notes=f"parse_error: {exc}",
            next_target="",
            next_prompt="",
            auto_advance=True,
        )
        _append_text(
            progress_path,
            (
                f"ingested_target={pending_target}\n"
                f"ingested_rank={state.get('pending_rank')}\n"
                f"ingested_verdict=needs_more_context\n"
                f"parse_error={exc}\n"
                f"response_archive={archive_path}\n"
                f"parse_error_file={parse_path}\n"
            ),
        )
        return {
            "target": pending_target,
            "rank": state.get("pending_rank"),
            "verdict": "needs_more_context",
            "next_target": "",
            "history_len": len(updated.get("history", [])),
        }
    next_target = parsed["next_target"] if parsed["should_continue"] else ""
    depth = int(state.get("manual_followup_depth", 0))
    if next_target and depth >= MAX_MANUAL_FOLLOWUPS:
        next_target = ""

    updated = record_review(
        session_dir=session_dir,
        rank=state.get("pending_rank"),
        target=pending_target,
        verdict=parsed["verdict"],
        notes=parsed["notes"],
        next_target=next_target,
        next_prompt="",
        auto_advance=True,
    )
    archive_path = _archive_response_file(session_dir, fixed_response)
    _append_text(
        progress_path,
        (
            f"ingested_target={pending_target}\n"
            f"ingested_rank={state.get('pending_rank')}\n"
            f"ingested_verdict={parsed['verdict']}\n"
            f"ingested_next_target={next_target}\n"
            f"response_archive={archive_path}\n"
        ),
    )
    if parsed["verdict"] in STRONG_FINDING_VERDICTS:
        finding_path = findings_dir / f"finding-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{_slugify(pending_target)[:60]}.txt"
        finding_body = (
            f"timestamp={datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')}\n"
            f"target={pending_target}\n"
            f"rank={state.get('pending_rank')}\n"
            f"verdict={parsed['verdict']}\n"
            f"next_target={next_target}\n"
            f"response_archive={archive_path}\n"
            "\n=== CODEX RESPONSE ===\n\n"
            f"{text.rstrip()}\n"
        )
        finding_path.write_text(finding_body, encoding="utf-8")
        _append_text(
            findings_path,
            (
                f"\n== FINDING {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\n"
                f"target={pending_target}\n"
                f"rank={state.get('pending_rank')}\n"
                f"verdict={parsed['verdict']}\n"
                f"next_target={next_target or 'none'}\n"
                f"details={finding_path}\n"
                f"archive={archive_path}\n"
            ),
        )
    return {
        "target": pending_target,
        "rank": state.get("pending_rank"),
        "verdict": parsed["verdict"],
        "next_target": next_target,
        "history_len": len(updated.get("history", [])),
    }


def _archive_response_file(session_dir: Path, fixed_response: Path) -> Path:
    archive_dir = response_archive_dir(session_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    archive_path = archive_dir / f"response-{stamp}.txt"
    fixed_response.replace(archive_path)
    return archive_path


def _render_next_prompt(session_dir: Path, *, include_snippet: bool) -> dict:
    manifest = _load_manifest(session_dir)
    state = load_state(session_dir)
    manual_target = (state.get("manual_next_target") or "").strip()
    manual_prompt = (state.get("manual_next_prompt") or "").strip()
    depth = int(state.get("manual_followup_depth", 0))

    if manual_target and depth >= MAX_MANUAL_FOLLOWUPS:
        state["manual_next_target"] = ""
        state["manual_next_prompt"] = ""
        state["manual_followup_depth"] = 0
        state["pending_rank"] = None
        state["pending_target"] = ""
        state["pending_prompt_source"] = ""
        save_state(session_dir, state)
        manual_target = ""
        manual_prompt = ""

    if manual_target:
        prompt_source = session_dir / "review_state.json"
        prompt = _manual_followup_prompt(state, manual_target, manual_prompt)
        set_pending_review(session_dir, None, manual_target, str(prompt_source))
        return {
            "repo_root": manifest["repo_root"],
            "prompt": prompt,
            "prompt_source": prompt_source,
            "snippet_path": None,
            "include_snippet": False,
            "target": manual_target,
            "rank": None,
        }

    rank, candidate = _next_pending_rank(state, manifest)
    prompt_path, snippet_path = _bundle_paths(session_dir, rank, candidate["path"])
    prompt = prompt_path.read_text(encoding="utf-8")
    set_pending_review(session_dir, rank, candidate["path"], str(prompt_path))
    return {
        "repo_root": manifest["repo_root"],
        "prompt": prompt,
        "prompt_source": prompt_path,
        "snippet_path": snippet_path,
        "include_snippet": include_snippet,
        "target": candidate["path"],
        "rank": rank,
    }


def _build_autopilot_prompt(rendered: dict) -> str:
    parts = [rendered["prompt"].rstrip()]
    if rendered.get("include_snippet") and rendered.get("snippet_path") and Path(rendered["snippet_path"]).exists():
        snippet = Path(rendered["snippet_path"]).read_text(encoding="utf-8").rstrip()
        if snippet:
            parts.extend(["", "Supplemental snippet from the harness:", snippet])
    parts.extend(
        [
            "",
            "Final response contract:",
            "Strict verdict:",
            "- one of: cve_candidate, plausible_security_bug, latent_bug, not_a_cve_candidate, needs_more_context",
            "",
            "Single best next target:",
            "- <file/function>",
            "- use `none` if this branch should stop and the harness should move to the next ranked target",
            "",
            "Summary:",
            "- 3 to 8 short lines only",
            "- include exact entrypoint, attacker control, and concrete impact reasoning",
        ]
    )
    return "\n".join(parts) + "\n"


def _manual_followup_prompt(state: dict, manual_target: str, manual_prompt: str) -> str:
    history = state.get("history", [])
    previous = history[-1] if history else {}
    lines = [
        "Continue from the previous audit.",
        "Do not restart broad review.",
        "",
        f"Previous verdict: {previous.get('verdict', '')}",
        f"Previous target: {previous.get('target', '')}",
    ]
    notes = (previous.get("notes") or "").strip()
    if notes:
        lines.append(f"Previous notes: {notes}")
    lines.extend(["", f"Now focus only on: {manual_target}"])
    if manual_prompt:
        lines.extend(["", manual_prompt.strip()])
    else:
        lines.extend(
            [
                "",
                "Requirements:",
                "1. Confirm the exact userspace-reachable entrypoint or caller path into this target.",
                "2. Validate concrete attacker control, object/length/state transition, and security impact.",
                "3. If nothing concrete exists, give a strict verdict and the single best next target.",
            ]
        )
    return "\n".join(lines) + "\n"


def _next_pending_rank(state: dict, manifest: dict) -> tuple[int, dict]:
    done = completed_ranks(state)
    candidates = manifest.get("candidates", [])
    start = max(1, int(state.get("current_rank", 1)))
    for rank in range(start, len(candidates) + 1):
        if rank in done:
            continue
        candidate = candidates[rank - 1]
        if _is_actionable_candidate(candidate.get("path", "")):
            return rank, candidate
    raise SystemExit("all ranked targets in this session have already been reviewed")


def _is_actionable_candidate(path: str) -> bool:
    lowered = path.lower()
    if lowered.startswith(("tools/", "samples/", "selftests/", "scripts/")):
        return False
    if "/test/" in lowered or "/tests/" in lowered:
        return False
    if lowered.startswith("lib/test_") or lowered.endswith("_test.c") or lowered.endswith("_test.h"):
        return False
    return True


def _bundle_paths(session_dir: Path, rank: int, rel_path: str) -> tuple[Path, Path]:
    bundle_dir = session_dir / "bundles"
    prefix = f"{rank:02d}-{rel_path.replace('/', '__')}"
    return bundle_dir / f"{prefix}.md", bundle_dir / f"{prefix}.snippet.txt"


def _load_manifest(session_dir: Path) -> dict:
    manifest_path = session_dir / "targets.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing session manifest: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def _append_text(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def _write_status(
    path: Path,
    *,
    stage: str,
    session_dir: Path,
    repo_root: str,
    started_at: datetime,
    duration_spec: str,
    runs: int,
    current_target: str = "",
    current_rank: int | None = None,
    last_target: str = "",
    last_verdict: str = "",
    last_next_target: str = "",
) -> None:
    state = load_state(session_dir)
    findings_count = len([item for item in state.get("history", []) if item.get("verdict") in STRONG_FINDING_VERDICTS])
    body = [
        f"stage={stage}",
        f"session={session_dir}",
        f"repo_root={repo_root}",
        f"started_at={started_at.strftime('%Y-%m-%d %H:%M:%SZ')}",
        f"duration={duration_spec}",
        f"runs={runs}",
        f"current_rank={state.get('current_rank', 1)}",
        f"manual_followup_depth={state.get('manual_followup_depth', 0)}",
        f"pending_rank={state.get('pending_rank')}",
        f"pending_target={state.get('pending_target', '')}",
        f"current_target={current_target}",
        f"current_rank_hint={current_rank}",
        f"last_target={last_target}",
        f"last_verdict={last_verdict}",
        f"last_next_target={last_next_target}",
        f"findings_count={findings_count}",
        f"fixed_response_file={response_path(session_dir)}",
    ]
    path.write_text("\n".join(body) + "\n", encoding="utf-8")


def _existing_run_count(prompts_dir: Path) -> int:
    return len(list(prompts_dir.glob("run-*.prompt.txt")))


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")
    return slug or "target"


def _parse_duration(spec: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([smh])\s*", spec.lower())
    if not match:
        raise SystemExit(f"invalid duration: {spec} (use forms like 30m, 1h, 45s)")
    value = int(match.group(1))
    unit = match.group(2)
    factors = {"s": 1, "m": 60, "h": 3600}
    return value * factors[unit]


def _ensure_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _has_nonempty_response(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0
