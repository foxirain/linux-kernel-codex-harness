from __future__ import annotations

from pathlib import Path

from kernel_harness.models import Candidate


KERNEL_AUDIT_PLAYBOOK = """\
You are auditing Linux kernel code for vulnerabilities that are realistic CVE candidates.

Prioritize:
- reachable attack surface from unprivileged or namespaced users
- memory corruption: UAF, OOB read/write, double-free, type confusion
- refcount, lock ordering, and lifetime bugs
- integer truncation/overflow leading to mis-sized allocations or copies
- info leaks to userspace
- missing privilege or namespace boundary checks

Treat findings as weak unless you can explain:
1. entrypoint and attacker control
2. exact object/length/state transition
3. failing invariant
4. crash, corruption, leak, or privilege outcome
5. why mitigations or checks do not block exploitation

When uncertain, request more context from nearby functions, structs, ops tables, and teardown paths before claiming a bug.
"""


def render_bundle_prompt(repo_root: Path, candidate: Candidate) -> str:
    rel_path = candidate.path.relative_to(repo_root)
    signals = "\n".join(
        f"- line {signal.line_no}: `{signal.name}` (+{signal.weight}) :: {signal.rationale}\n  code: `{signal.line[:160]}`"
        for signal in candidate.signals
    )
    if not signals:
        signals = "- no line-level signals captured"

    reasons = "\n".join(f"- {reason}" for reason in candidate.reasons[:12])
    external = "\n".join(
        f"- {signal.summary} (+{signal.weight}) [{signal.source}] {signal.url}".rstrip()
        for signal in candidate.external_signals[:6]
    )
    if not external:
        external = "- no external crash intelligence attached"

    return f"""\
{KERNEL_AUDIT_PLAYBOOK}

Target file: `{rel_path}`
Subsystem: `{candidate.subsystem}`
Likely entrypoint: `{candidate.entrypoint}`
Priority score: `{candidate.score}`

Why this file was selected:
{reasons}

Observed signals:
{signals}

syzbot context:
{external}

Audit workflow:
1. Identify the actual userspace-reachable entrypoint and name the caller-controlled fields.
2. Map allocation, refcount, and free paths touched by those fields.
3. Trace copy lengths, array indices, object sizes, and cast boundaries.
4. Check lock/RCU assumptions against async teardown, error unwind, and retry paths.
5. If syzbot context exists, test whether this code shares the same broken invariant, an incomplete fix, or a nearby variant.
6. Decide whether the issue is a plausible CVE candidate. If yes, produce a report with:
   - title
   - bug class
   - impact
   - reachability
   - evidence
   - exploit sketch
   - confidence 1-10
7. If no bug is confirmed, state the best next files/functions to inspect.

Kernel-specific prompts:
- Compare fast path and error path state transitions.
- Compare compat handlers with native handlers.
- Check capability checks happen before dereferencing or allocation side effects.
- Look for reference increments that are not paired on all exits.
- Look for sizes derived from userspace then widened/narrowed before allocation or copy.
- Treat syzbot crashes as hints, not proof. Confirm the exact invariant break yourself.
"""
