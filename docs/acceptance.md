# MVP acceptance baseline

Task 38의 acceptance runner는 고정 fixture version과 seed로 MVP 범위를 반복 검증한다. 이 결과는 통제된 fixture의 **MVP acceptance baseline**이며, 운영 환경에서의 production SLO 약속이나 가용성 보증이 아니다.

다음 명령은 JSON과 사람이 읽는 Markdown 요약을 `acceptance-results/`에 만든다. `GO`는 현재 Go toolchain의 절대 경로 또는 PATH에서 해석 가능한 `go`여야 한다.

```text
make acceptance GO=/path/to/go
```

명시적 출력 경로가 필요하면 동일한 단일 바이너리 CLI를 사용한다.

```text
pulse-agent acceptance run --output /var/tmp/pulse-agent-acceptance --go-bin /path/to/go
```

생성 파일은 다음과 같다.

- `mvp-acceptance.json`: seed, fixture version, 감지·복구·보안·보고·관리 CLI/approval/webhook 계약과 각 품질 게이트의 pass/fail 결과
- `mvp-acceptance-summary.md`: 사람이 읽는 기준 요약과 실패 reason

runner는 100개 controlled fault/normal detection scenario, 100개 단일 container 또는 정확히 1-replica Compose recovery run, 100개 security corpus와 restart recovery를 평가한다. 0·2·3 replica selector는 Docker 상태 변경 0건이어야 한다. 보고서는 필수 종료 필드와 60초 내 전달 또는 retry-pending을 기록한다.

`go test ./...`, `go test -race ./...`, `go vet ./...`, scheduler cancellation과 bounded shutdown을 확인하는 targeted test가 모두 quality gate다. 하나라도 실패하거나 수치 기준을 충족하지 않으면 runner는 실패 exit code를 반환하되, 조사할 수 있도록 두 결과 파일은 남긴다.

실행은 기존 Go 테스트만 사용하며 새 linter나 외부 서비스에 의존하지 않는다. fixture와 기존 테스트는 synthetic·마스킹 데이터만 사용하며, API key·원본 evidence·실제 운영 로그를 결과 파일에 기록하지 않는다.
