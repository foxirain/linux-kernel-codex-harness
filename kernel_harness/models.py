from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Signal:
    name: str
    weight: int
    line_no: int
    line: str
    rationale: str


@dataclass(slots=True)
class ExternalSignal:
    source: str
    weight: int
    summary: str
    url: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class Candidate:
    path: Path
    subsystem: str
    entrypoint: str
    score: int
    signals: list[Signal] = field(default_factory=list)
    path_signals: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    external_signals: list[ExternalSignal] = field(default_factory=list)

    def to_dict(self, repo_root: Path) -> dict:
        return {
            "path": str(self.path.relative_to(repo_root)),
            "subsystem": self.subsystem,
            "entrypoint": self.entrypoint,
            "score": self.score,
            "path_signals": self.path_signals,
            "reasons": self.reasons,
            "signals": [
                {
                    "name": signal.name,
                    "weight": signal.weight,
                    "line_no": signal.line_no,
                    "line": signal.line,
                    "rationale": signal.rationale,
                }
                for signal in self.signals
            ],
            "external_signals": [
                {
                    "source": signal.source,
                    "weight": signal.weight,
                    "summary": signal.summary,
                    "url": signal.url,
                    "metadata": signal.metadata,
                }
                for signal in self.external_signals
            ],
        }
