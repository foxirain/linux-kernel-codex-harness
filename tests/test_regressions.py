from __future__ import annotations

import argparse
import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path

from kernel_harness import cli
from kernel_harness.autopilot import _ingest_pending_response, _render_next_prompt
from kernel_harness.bundle import write_session_bundle
from kernel_harness.ingest import parse_response
from kernel_harness.models import Candidate, Signal
from kernel_harness.session import load_state, record_review, response_path
from kernel_harness.targeting import discover_candidates, load_config


class HarnessRegressionTests(unittest.TestCase):
    def test_allocator_rules_match_kmalloc_and_kvmalloc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir)
            source_dir = repo_root / "kernel"
            source_dir.mkdir()
            (source_dir / "alloc.c").write_text(
                "void *a = kmalloc(size, GFP_KERNEL);\n"
                "void *b = kvmalloc(size, GFP_KERNEL);\n",
                encoding="utf-8",
            )

            config = load_config(cli.PROFILE_CONFIGS["default"])
            candidates = discover_candidates(repo_root, config=config, limit=10)

            self.assertEqual(len(candidates), 1)
            allocator_hits = [signal for signal in candidates[0].signals if signal.name == "allocator"]
            self.assertEqual([signal.line_no for signal in allocator_hits], [1, 2])

    def test_all_builtin_profiles_are_packaged_and_loadable(self) -> None:
        self.assertEqual(set(cli.PROFILE_CONFIGS), {"default", "bpf", "drivers", "fs", "io_uring", "net"})
        loaded_configs = [load_config(None)]
        for profile_path in cli.PROFILE_CONFIGS.values():
            with self.subTest(profile=profile_path.name):
                self.assertTrue(profile_path.is_file())
                config = load_config(profile_path)
                self.assertIn("patterns", config)
                loaded_configs.append(config)

        for config in loaded_configs:
            allocator_patterns = [item["pattern"] for item in config["patterns"] if item["name"] == "allocator"]
            for pattern in allocator_patterns:
                with self.subTest(pattern=pattern):
                    self.assertIsNotNone(re.search(pattern, "kmalloc"))
                    self.assertIsNotNone(re.search(pattern, "kvmalloc"))

    def test_two_manual_followups_run_and_third_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir = Path(temp_dir) / "session"
            write_session_bundle(Path.cwd(), session_dir, [], top_n=0)

            record_review(
                session_dir,
                rank=1,
                target="kernel/start.c",
                verdict="needs_more_context",
                notes="",
                next_target="kernel/first.c",
                next_prompt="",
                auto_advance=True,
            )
            first = _render_next_prompt(session_dir, include_snippet=False)
            self.assertEqual(first["target"], "kernel/first.c")

            cli._ingest_text(
                session_dir,
                self._response("kernel/second.c"),
                rank=None,
                target="kernel/first.c",
                next_prompt="",
                auto_advance=True,
            )
            second = _render_next_prompt(session_dir, include_snippet=False)
            self.assertEqual(second["target"], "kernel/second.c")

            state = cli._ingest_text(
                session_dir,
                self._response("kernel/third.c"),
                rank=None,
                target="kernel/second.c",
                next_prompt="",
                auto_advance=True,
            )
            self.assertEqual(state["manual_followup_depth"], 0)
            self.assertEqual(state["manual_next_target"], "")

    def test_manual_loop_archives_unmatched_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo_root = root / "tree"
            source_path = repo_root / "kernel" / "entry.c"
            source_path.parent.mkdir(parents=True)
            source_path.write_text("void entry(void) {}\n", encoding="utf-8")
            candidate = Candidate(
                path=source_path,
                subsystem="kernel",
                entrypoint="entry",
                score=10,
                signals=[Signal("user_pointer", 6, 1, "void entry(void) {}", "test signal")],
            )
            session_dir = root / "session"
            write_session_bundle(repo_root, session_dir, [candidate], top_n=1)
            response_path(session_dir).write_text(self._response("none"), encoding="utf-8")

            args = argparse.Namespace(session_dir=session_dir, include_snippet=False, next_prompt="")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli._run_loop(args), 0)

            self.assertFalse(response_path(session_dir).exists())
            self.assertEqual(len(list((session_dir / "responses").glob("stale-response-*.txt"))), 1)
            self.assertEqual(load_state(session_dir)["pending_target"], "kernel/entry.c")

    def test_autopilot_archives_unmatched_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_dir = Path(temp_dir) / "session"
            write_session_bundle(Path.cwd(), session_dir, [], top_n=0)
            response_path(session_dir).write_text(self._response("none"), encoding="utf-8")
            autopilot_dir = session_dir / "autopilot"
            findings_dir = autopilot_dir / "findings"
            findings_dir.mkdir(parents=True)

            result = _ingest_pending_response(
                session_dir,
                findings_dir,
                autopilot_dir / "AUTOPILOT_FINDINGS.txt",
                autopilot_dir / "AUTOPILOT_PROGRESS.txt",
            )

            self.assertIsNone(result)
            self.assertFalse(response_path(session_dir).exists())
            self.assertEqual(len(list((session_dir / "responses").glob("response-*.txt"))), 1)
            progress = (autopilot_dir / "AUTOPILOT_PROGRESS.txt").read_text(encoding="utf-8")
            self.assertIn("stale_response_without_pending_target=1", progress)

    def test_response_contract_and_safe_sandbox_default(self) -> None:
        parsed = parse_response(self._response("none"))
        self.assertEqual(parsed["verdict"], "not_cve_candidate")
        self.assertFalse(parsed["should_continue"])

        args = cli.build_parser().parse_args(["autopilot", "/tmp/session"])
        self.assertEqual(args.sandbox, "read-only")

    @staticmethod
    def _response(next_target: str) -> str:
        return (
            "Strict verdict:\n"
            "- not_cve_candidate\n\n"
            "Single best next target:\n"
            f"- {next_target}\n\n"
            "Summary:\n"
            "- no concrete vulnerability found\n"
        )


if __name__ == "__main__":
    unittest.main()
