# Autopilot Workflow

이제는 수동 `loop` 대신 시간 예산 기반의 비대화식 실행이 가능하다.

## 핵심 명령

```bash
python3 -m kernel_harness autopilot /linux_harness/artifacts/session-YYYYMMDDTHHMMSSZ \
  --duration 1h \
  --per-run-timeout 20m \
  --include-snippet
```

이 명령은 예산이 끝날 때까지 다음 순서로 자동 반복한다.

1. 다음 타깃 프롬프트 생성
2. `codex exec` 비대화식 실행
3. 응답 자동 ingest
4. verdict 기록
5. 같은 줄기를 더 팔지, 다음 rank로 갈지 결정
6. 진행 로그와 finding 로그 갱신

## 로그 파일

세션 아래에 `autopilot/` 디렉터리가 생긴다.

- `AUTOPILOT_STATUS.txt`
  현재 무엇을 분석 중인지, 현재 rank, 마지막 verdict, pending target 요약
- `AUTOPILOT_PROGRESS.txt`
  실행 이력 전체. 언제 어떤 파일/함수를 분석했는지, 어느 프롬프트를 썼는지, 어떤 verdict가 나왔는지 순서대로 남김
- `AUTOPILOT_FINDINGS.txt`
  `cve_candidate` 또는 `plausible_security_bug`가 나오면 요약을 누적
- `findings/finding-*.txt`
  강한 finding이 잡혔을 때 Codex 원문 응답 전체를 별도 파일로 저장
- `prompts/run-*.prompt.txt`
  각 반복에서 Codex에 실제로 넣은 프롬프트
- `exec/run-*.stdout.txt`
  각 반복의 `codex exec` 표준출력
- `exec/run-*.stderr.txt`
  각 반복의 `codex exec` 표준에러

## 운용 옵션

```bash
python3 -m kernel_harness autopilot SESSION \
  --duration 2h \
  --per-run-timeout 15m \
  --model gpt-5.4 \
  --include-snippet \
  --stop-on-finding
```

옵션 설명:

- `--duration`
  전체 실행 시간. `30m`, `1h`, `45s` 형식
- `--per-run-timeout`
  Codex 한 번 실행의 최대 시간
- `--include-snippet`
  스니펫까지 프롬프트에 포함
- `--model`
  특정 Codex 모델 지정
- `--stop-on-finding`
  강한 finding이 나오면 즉시 중단
- `--no-full-auto`
  `codex exec --full-auto`를 빼고 직접 sandbox 모드만 적용
- `--sandbox`
  `read-only`, `workspace-write`, `danger-full-access`
- `--dangerously-bypass-approvals-and-sandbox`
  Codex CLI의 위험 플래그를 그대로 전달

## same-branch 정책

하네스는 Codex가 계속 인접 함수만 추천해도 무한히 따라가지 않는다.

- 같은 줄기의 manual follow-up은 최대 2번까지 허용
- 그 이후에도 `not_cve_candidate`가 계속 나오면 자동으로 다음 rank로 이동
- `tools/`, `samples/`, `selftests/`, `lib/test_*` 같은 테스트성 파일은 자동으로 건너뜀

## 상태 확인

```bash
python3 -m kernel_harness status /linux_harness/artifacts/session-YYYYMMDDTHHMMSSZ
cat /linux_harness/artifacts/session-YYYYMMDDTHHMMSSZ/autopilot/AUTOPILOT_STATUS.txt
```

실행 중인지 확인하려면 `AUTOPILOT_STATUS.txt`와 `AUTOPILOT_PROGRESS.txt`를 보면 된다.
