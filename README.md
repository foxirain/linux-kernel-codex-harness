# Kernel Codex Harness

[![CI](https://github.com/foxirain/linux-kernel-codex-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/foxirain/linux-kernel-codex-harness/actions/workflows/ci.yml)

> **Status — archived portfolio project.** Linux 커널 취약점 조사에서 LLM의 탐색 범위를 어떻게 좁힐지 실험한 프로젝트입니다. 실제 취약점을 증명하거나 보안성을 보장하는 도구는 아닙니다.

`Kernel Codex Harness`는 Linux 커널 소스 트리에서 userspace-reachable attack surface와 취약점 관련 신호를 점수화하고, Codex가 바로 조사할 수 있는 타깃별 프롬프트와 상태 기반 검토 세션을 생성합니다.

## 해결하려던 문제

Linux 커널 전체를 LLM에 넓게 탐색시키면 다음 문제가 생깁니다.

- 코드베이스가 너무 커서 조사 컨텍스트가 빠르게 분산됩니다.
- 높은 점수의 정적 패턴도 실제 userspace reachability가 없으면 보안 이슈가 아닙니다.
- 한 타깃에서 추가 caller, teardown, free path를 찾는 과정이 반복됩니다.
- 여러 번의 모델 실행 결과를 같은 기준으로 기록하고 다음 타깃으로 넘기기 어렵습니다.

이 프로젝트는 취약점을 직접 판정하는 대신, **조사할 가치가 높은 파일을 먼저 좁히고 검토 흐름을 재현 가능하게 만드는 것**에 집중했습니다.

## 설계 철학

1. **Prioritize, do not prove**
   정규식과 경로 점수는 증거가 아니라 조사 순서를 정하는 힌트로만 사용합니다.
2. **Reachability first**
   `syscall`, `ioctl`, `netlink`, `procfs`, `BPF`, filesystem, driver 경계처럼 userspace에서 도달 가능한 진입점을 먼저 확인합니다.
3. **One branch at a time**
   한 번에 한 파일과 짧은 follow-up만 허용해 모델 컨텍스트가 불필요하게 확장되는 것을 막습니다.
4. **Evidence over generic advice**
   attacker control, 깨지는 invariant, 구체적 impact를 설명하지 못하면 강한 finding으로 취급하지 않습니다.
5. **Persist the investigation**
   후보 점수, 프롬프트, 응답, verdict, 다음 타깃을 파일 기반 세션으로 남겨 실행 과정을 다시 확인할 수 있게 합니다.

초기 아이디어는 Protect AI의 [vulnhuntr](https://github.com/protectai/vulnhuntr)에서 사용한 `entrypoint prioritization → context expansion → structured result` 흐름에서 영감을 받았고, 이를 Linux 커널의 lifetime, usercopy, refcount, size 검증 문제에 맞게 조정했습니다.

## 동작 구조

```text
Linux kernel tree
  + subsystem profile
  + optional syzbot cache
          │
          ▼
  heuristic targeting
          │
          ▼
   ranked candidates
          │
          ▼
 prompt/snippet bundles
          │
          ├── manual Codex workflow
          └── time-budgeted autopilot
                    │
                    ▼
          verdict + next target
                    │
                    ▼
          review state + findings
```

주요 모듈의 책임은 다음과 같습니다.

| 모듈 | 역할 |
| --- | --- |
| `targeting.py` | 커널 파일 탐색, 정규식·경로·syzbot 점수화 |
| `models.py` | `Candidate`, `Signal`, `ExternalSignal` 모델 |
| `bundle.py` / `prompting.py` | 세션 인덱스, 프롬프트, 코드 스니펫 생성 |
| `session.py` / `ingest.py` | 검토 상태 저장과 Codex 응답 계약 해석 |
| `autopilot.py` | 시간 예산 기반 `codex exec` 반복 실행과 로그 보존 |
| `syzbot.py` | 공개 syzbot 페이지 수집과 로컬 JSON 캐시 생성 |

## 탐지 신호와 프로필

기본 스캐너는 다음 신호를 조합합니다.

- `ioctl`, compat handler, file operation hook
- `copy_from_user`, `copy_to_user`, `__user`
- `kmalloc`, `kzalloc`, `kvmalloc`, cache allocation과 free path
- refcount, atomic, kref 연산
- size와 length 계산, memcpy 계열
- lock, RCU, async lifetime 관련 패턴
- BPF, skb, XDP, netlink 경계
- capability와 namespace check
- syzbot file/subsystem overlap

내장 프로필은 `default`, `net`, `fs`, `io_uring`, `bpf`, `drivers`입니다. 각 프로필은 조사 범위와 가중치를 좁혀 전체 커널을 한 세션에서 과도하게 훑지 않도록 합니다.

## 요구사항과 설치

- Python 3.11 이상
- autopilot 사용 시 [Codex CLI](https://developers.openai.com/codex/cli/)와 인증
- `syzbot-fetch`로 원격 URL을 읽을 때만 네트워크 연결

```bash
git clone https://github.com/foxirain/linux-kernel-codex-harness.git
cd linux-kernel-codex-harness

python3 -m venv .venv
source .venv/bin/activate
python -m pip install .

kernel-harness --help
```

내장 프로필은 wheel에 함께 포함되므로 설치 후 별도 config 경로를 지정하지 않아도 됩니다. 직접 만든 JSON 규칙은 `--config /path/to/profile.json`으로 전달할 수 있습니다.

## 2분 Quick Start

세션을 생성합니다.

```bash
kernel-harness scan /path/to/linux \
  --profile net \
  --limit 80 \
  --top 20 \
  --out artifacts
```

`--limit`은 유지할 후보 수이고, `--top`은 처음에 미리 만들 prompt bundle 수입니다. 이후 rank의 bundle도 요청 시 생성할 수 있습니다.

상위 후보를 확인합니다.

```bash
kernel-harness inspect artifacts/session-YYYYMMDDTHHMMSSZ --top 10
```

수동 조사 프롬프트를 출력합니다.

```bash
kernel-harness codex artifacts/session-YYYYMMDDTHHMMSSZ \
  --rank 1 \
  --include-snippet
```

시간 예산 기반 autopilot을 실행할 수도 있습니다.

```bash
kernel-harness autopilot artifacts/session-YYYYMMDDTHHMMSSZ \
  --duration 30m \
  --per-run-timeout 10m \
  --include-snippet
```

autopilot의 기본 sandbox는 `read-only`입니다. 조사 과정에서 파일 변경이 정말 필요한 경우에만 `--sandbox workspace-write`를 명시해야 합니다.

## syzbot 신호 추가

```bash
kernel-harness syzbot-fetch https://syzkaller.appspot.com/upstream \
  --out artifacts/syzbot/upstream.json \
  --limit 50

kernel-harness scan /path/to/linux \
  --profile fs \
  --syzbot-json artifacts/syzbot/upstream.json \
  --out artifacts
```

syzbot overlap은 실제 크래시와 가까운 코드를 먼저 보게 하는 힌트입니다. 같은 파일 또는 subsystem에서 crash가 있었다는 사실만으로 새로운 취약점이 입증되지는 않습니다.

## 세션 산출물

```text
artifacts/session-<timestamp>/
├── SESSION.md
├── targets.json
├── finding_template.json
├── review_state.json
├── codex_response.txt              # pending response가 있을 때
├── bundles/
│   ├── <rank>-<target>.md
│   └── <rank>-<target>.snippet.txt
├── responses/                      # ingest된 응답 archive
└── autopilot/
    ├── AUTOPILOT_STATUS.txt
    ├── AUTOPILOT_PROGRESS.txt
    ├── AUTOPILOT_FINDINGS.txt
    ├── prompts/
    ├── exec/
    └── findings/
```

모델 응답은 다음 다섯 verdict 중 하나로 정규화됩니다.

- `cve_candidate`
- `plausible_security_bug`
- `latent_bug`
- `not_cve_candidate`
- `needs_more_context`

응답에는 하나의 `Single best next target`만 허용하며, 같은 조사 분기의 manual follow-up은 최대 두 번으로 제한합니다.

## 테스트와 CI

```bash
python -m unittest discover -s tests -v
```

회귀 테스트는 allocator 탐지, profile 리소스 로딩, verdict 파싱, follow-up 깊이, stale response 격리, 안전한 sandbox 기본값을 확인합니다.

GitHub Actions는 Python 3.11과 3.12에서 테스트를 실행하고, wheel을 새로 설치한 환경에서 내장 profile 스캔이 동작하는지도 확인합니다.

## 저장소 구조

```text
.
├── .github/workflows/ci.yml
├── docs/
│   ├── AUTOPILOT.md
│   ├── CODEX_CLI.md
│   ├── CODEX_WORKFLOW.md
│   └── SYZBOT.md
├── kernel_harness/
│   ├── resources/
│   │   ├── linux-kernel-default.json
│   │   └── profiles/
│   ├── autopilot.py
│   ├── bundle.py
│   ├── cli.py
│   ├── ingest.py
│   ├── models.py
│   ├── prompting.py
│   ├── session.py
│   ├── syzbot.py
│   └── targeting.py
├── tests/test_regressions.py
├── README.md
└── pyproject.toml
```

## 한계와 trade-off

- 실제 C AST, call graph, interprocedural data flow를 만들지 않습니다.
- 정규식 기반이므로 주석, 매크로, 반복 토큰과 큰 파일이 점수에 영향을 줄 수 있습니다.
- 커널 config, privilege, namespace, device availability에 따른 실제 reachability를 자동 증명하지 않습니다.
- syzbot 연동은 공개 HTML 구조를 파싱하므로 대시보드 변경의 영향을 받을 수 있습니다.
- Codex verdict는 조사 결과이지 보안 보고서의 최종 증거가 아닙니다.
- 실제 finding은 caller, teardown, error path, exploit impact를 사람이 다시 검증해야 합니다.

이 trade-off는 정밀 정적 분석기를 만드는 대신, 구현이 단순하고 각 점수의 이유를 설명할 수 있는 조사 우선순위 도구를 빠르게 실험하기 위한 선택이었습니다.

## 회고: 지금 다시 만든다면

당시에는 파일 단위 점수화와 프롬프트 오케스트레이션을 먼저 검증하는 것이 목표였습니다. 지금 다시 만든다면 다음 순서로 발전시킬 것입니다.

1. tree-sitter 또는 Clang 기반 symbol/call graph를 추가합니다.
2. 파일 크기와 반복 hit를 정규화하고 profile별 calibration fixture를 만듭니다.
3. `review`와 `runner` 계층을 분리해 CLI와 autopilot의 중복을 줄입니다.
4. session manifest와 state에 명시적 schema version과 atomic write를 적용합니다.
5. 모델 응답을 JSON Schema로 제한하고 finding evidence를 구조화합니다.
6. syzbot crash를 실제 fix commit과 연결해 variant hunting 신호를 강화합니다.

그럼에도 현재 구조에서 유지하고 싶은 핵심은 같습니다. **LLM에게 코드베이스 전체를 막연하게 탐색시키지 않고, reachability와 invariant를 중심으로 좁은 조사 단위를 반복한다는 것**입니다.

## 안전 주의사항

- 기본 `read-only` sandbox를 유지하는 것을 권장합니다.
- 외부 sandbox가 없는 환경에서는 `--dangerously-bypass-approvals-and-sandbox`를 사용하지 마세요.
- 신뢰할 수 없는 커널 트리의 코드와 주석은 모델 입력이 되므로 prompt injection 가능성을 고려해야 합니다.
- 생성된 finding을 공개하거나 보고하기 전에 반드시 사람이 재현성과 영향을 검증해야 합니다.

세부 운영법은 [`docs/`](docs/)에서 확인할 수 있습니다.
