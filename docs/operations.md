# Pulse Agent Linux 운영 가이드

이 문서는 systemd 기반 Linux 호스트의 Standalone 프로필만 다룬다. Pulse Agent를 감시 대상 컨테이너 안에 배포하거나 Docker socket을 컨테이너에 전달하지 않는다. 클러스터 제어와 임의 host shell/command 실행도 지원하지 않는다.

## 보안 경계와 알려진 한계

- `/var/run/docker.sock` 접근은 컨테이너 생성, mount, 프로세스 제어로 이어질 수 있는 host root에 준하는 높은 로컬 권한이다. `pulse-agent` 전용 system account만 `docker` 그룹에 넣고 일반 사용자에게 이 계정이나 환경 파일 접근을 허용하지 않는다.
- Pulse Agent는 등록된 target과 typed Docker action만 다룬다. raw host command, shell, script, 임의 argv는 지원하지 않는다.
- Standalone 프로세스는 자신이 실행 중인 머신 전체의 전원 상실, OS 정지, host network 단절 자체를 그 머신 안에서 감지하거나 통지할 수 없다. 이 장애는 외부 모니터가 담당해야 한다.
- `pulse-agent status`는 위 항목을 안정적인 코드로 표시한다. `warnings`에는 `docker_socket_high_privilege`, `unsupported`에는 `raw_host_command`와 `host_power_os_network_outage`가 포함되어야 한다.

## 재현 가능한 단일 바이너리

릴리스에 고정한 Go 1.25 이상 toolchain과 저장소의 `go.sum`을 사용한다. 기본 amd64 빌드와 바이트 동일성 검사는 다음과 같다.

```text
make build-linux
make reproducible-linux
sha256sum dist/pulse-agent-linux-amd64
```

arm64는 `make build-linux GOARCH=arm64`를 사용한다. 결과물은 외부 shared library가 필요 없는 `pulse-agent` 바이너리 하나다. 서로 다른 Go toolchain이나 `GOARCH` 결과의 digest가 같을 것이라고 가정하지 않는다.

## 설치

Docker Engine과 `docker` 그룹이 먼저 존재해야 한다. 빌드 산출물과 저장소의 packaging 파일을 검토한 후 다음 경로에 설치한다.

```text
sudo install -o root -g root -m 0755 dist/pulse-agent-linux-amd64 /usr/local/bin/pulse-agent
sudo install -o root -g root -m 0644 packaging/sysusers.d/pulse-agent.conf /usr/lib/sysusers.d/pulse-agent.conf
sudo install -o root -g root -m 0644 packaging/tmpfiles.d/pulse-agent.conf /usr/lib/tmpfiles.d/pulse-agent.conf
sudo systemd-sysusers /usr/lib/sysusers.d/pulse-agent.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/pulse-agent.conf
sudo install -o root -g pulse-agent-admin -m 0640 packaging/examples/config.json /etc/pulse-agent/config.json
sudo install -o pulse-agent -g pulse-agent-admin -m 0600 packaging/pulse-agent.env.example /etc/pulse-agent/pulse-agent.env
sudo install -o root -g root -m 0644 packaging/systemd/pulse-agent.service /etc/systemd/system/pulse-agent.service
```

서비스는 `pulse-agent` 사용자, `pulse-agent-admin` primary group, `docker` supplementary group으로 실행된다. `/var/lib/pulse-agent`는 `0750`, evidence 디렉터리는 `0700`, state database는 daemon이 `0600`, 관리 Unix socket은 daemon이 `0660`으로 만든다.

관리 사용자는 socket 파일 접근을 위해 `pulse-agent-admin` supplementary group에 추가한다. IPC는 Linux peer credential의 UID와 primary GID를 **모두** 대조하므로, 각 관리자의 `id -u`와 `id -g` 값을 `admin.allowed_uids`와 `admin.allowed_gids`에 명시해야 한다. 예제의 `0/0`은 `sudo`로 실행한 root 관리 요청만 허용한다. 그룹 가입만으로 IPC allowlist를 우회할 수 없다.

## 설정과 데몬 없는 검증

`/etc/pulse-agent/config.json`의 endpoint, target allowlist, UID/GID를 호스트에 맞게 변경한다. secret 원문은 JSON에 넣지 않고 `env:NAME` reference만 둔다. `/etc/pulse-agent/pulse-agent.env`에는 실제 값을 배포 시스템이나 secret manager가 로컬에서 기록하고 계속 `0600`을 유지한다.

다음 검증은 daemon, database, Docker 또는 외부 network에 접속하지 않는 읽기 전용 검사다. secret reference를 확인하지만 secret 값을 읽지 않는다.

```text
sudo /usr/local/bin/pulse-agent config validate --config /etc/pulse-agent/config.json
/usr/local/bin/pulse-agent runbook validate --runbook /absolute/path/to/restart-checkout
```

runbook의 Markdown은 설명이고 `runbook.json`의 strict typed action만 실행 계약이다. 검증이 성공한 뒤에만 서비스를 시작한다.

```text
sudo systemctl daemon-reload
sudo systemctl enable --now pulse-agent.service
sudo /usr/local/bin/pulse-agent status --config /etc/pulse-agent/config.json --reason operator_status
```

## 등록과 승인

target 문서와 runbook pair는 먼저 로컬에서 검토한 뒤 daemon-owned IPC로 등록한다. 아래 옵션 순서는 현재 CLI 계약과 같다.

```text
sudo /usr/local/bin/pulse-agent target register --config /etc/pulse-agent/config.json --target /absolute/path/to/target.json --reason onboarding
sudo /usr/local/bin/pulse-agent runbook register --config /etc/pulse-agent/config.json --runbook /absolute/path/to/restart-checkout --reason onboarding
sudo /usr/local/bin/pulse-agent approval grant --config /etc/pulse-agent/config.json --command-id command-123 --expires-at 2026-07-22T04:00:00Z --reason operator_approved
sudo /usr/local/bin/pulse-agent approval deny --config /etc/pulse-agent/config.json --command-id command-123 --expires-at 2026-07-22T04:00:00Z --reason operator_denied
```

승인은 command ID와 만료 시각이 정확히 일치하는 경우에만 부여한다. 운영 문서나 model 응답의 command 문자열을 직접 실행하지 않는다.

## Gemini 데이터 처리

- 무료 AI Studio/Gemini 프로젝트와 `data_processing_mode: unpaid_or_free`는 synthetic fixture만 처리하는 `usage_mode: synthetic_development` 전용이다. 고객 로그, PII, 실제 incident evidence를 보내지 않는다.
- 실제 운영은 billing-enabled 프로젝트, `usage_mode: production`, `data_processing_mode: billing_enabled`, 전송 전 redaction을 모두 요구한다. redaction 실패 시 evidence 전송은 fail-closed되어야 한다.
- `data_processing_mode`는 운영자의 명시적 선언이다. config validation은 Gemini billing API를 조회하지 않으며 실제 결제 활성화나 provider의 데이터 처리 조건을 자동 판별·보장하지 않는다. 배포 전 Gemini 콘솔과 조직 정책에서 별도로 확인한다.
- API key는 `gemini.api_key_ref`가 가리키는 환경 변수로만 공급하고 log, shell history, ticket, config JSON에 원문을 남기지 않는다.

## Standard Webhooks

### Secret과 reference

current secret은 `whsec_` 뒤에 24~64바이트의 base64 값이 붙는 Standard Webhooks 형식이어야 한다. secret manager에서 32 random bytes를 생성해 `/etc/pulse-agent/pulse-agent.env`의 referenced 환경 변수에 배포한다. 문서나 저장소에 생성 결과를 출력하지 않는다. JSON에는 `secret_ref`와 선택적인 `previous_secret_ref`만 기록한다.

### Timestamp, clock, replay

서명 대상은 `webhook-id.webhook-timestamp.`와 **수신한 exact raw body**의 결합이다. `webhook-id`, `webhook-timestamp`, `webhook-signature` 세 header가 필요하고 허용 timestamp 차이는 과거·미래 모두 5분이다. 모든 송수신 host에서 NTP를 활성화하고 `timedatectl status`로 동기화 상태를 확인한다.

수신자는 이미 수락한 `webhook-id`를 durable receipt로 기록해 같은 ID의 replay를 거부한다. 재전송할 때 logical delivery의 ID와 raw body를 유지해야 하며, 새 ID로 바꿔 replay 방어를 우회하지 않는다. 5분을 넘긴 서명은 새 timestamp와 유효한 signer로 다시 서명해야 한다.

### Current/previous rotation

1. 새 current secret을 생성하고 기존 current 값을 `*_SECRET_PREVIOUS`에 옮긴다.
2. `secret_ref`는 새 current, `previous_secret_ref`는 이전 secret의 환경 변수 reference가 되게 배포한 후 서비스를 재시작한다.
3. 양쪽 endpoint가 새 secret을 사용하는지 확인한다. 전환 중 verifier는 current와 previous를 모두 허용하고 signer는 rotation signature를 함께 낼 수 있다.
4. 최소 5분의 timestamp 허용 구간과 clock skew가 지난 뒤에도 delivery retry가 남았는지 확인한다. 모든 peer 전환과 pending retry 소진을 확인한 후 previous reference와 값을 제거하고 다시 시작한다.

current와 previous를 같은 값으로 설정하면 config validation이 거부한다. 동시에 세 개 이상의 secret을 운용하지 않는다.

### Delivery 진단

1. `pulse-agent status`로 daemon IPC가 `running`인지 확인하고 `journalctl -u pulse-agent.service`에서 bounded reason code만 확인한다. payload, header 전체, endpoint credential, secret은 ticket이나 log에 복사하지 않는다.
2. 송수신 host clock과 5분 허용 범위를 확인한다.
3. 세 Standard Webhooks header 이름, exact raw body 보존, `v1` signature, current/previous reference를 양쪽에서 확인한다.
4. outbound endpoint가 HTTPS이고 2xx를 반환하는지 수신 측에서 확인한다. timeout, 비-2xx, endpoint 실패는 bounded backoff로 retry되므로 daemon 재시작으로 queue를 삭제하거나 같은 logical delivery를 새 ID로 수동 재생성하지 않는다.
5. `signature_mismatch`, `timestamp_outside_tolerance`, duplicate/replay, terminal delivery reason을 구분한 뒤 원인을 수정한다. raw secret을 비교하지 말고 reference 이름과 rotation 단계만 비교한다.

## Backup과 restore

daemon이 실행 중일 때도 `backup`은 일관된 database snapshot을 stdout으로 보낸다. 임시 파일을 `0600`으로 만들고 성공한 결과만 확정 이름으로 이동한다.

```text
umask 077
sudo /usr/local/bin/pulse-agent backup --config /etc/pulse-agent/config.json --reason routine_backup > /secure/path/pulse-agent.db.tmp
sha256sum /secure/path/pulse-agent.db.tmp
mv /secure/path/pulse-agent.db.tmp /secure/path/pulse-agent.db
```

현재 CLI에는 restore subcommand가 없다. 다음은 daemon을 중지하고 기존 파일을 보존하는 수동 복구 절차다.

1. backup digest와 파일 크기를 승인된 기록과 비교한다.
2. `sudo systemctl stop pulse-agent.service` 후 프로세스와 `/var/lib/pulse-agent/admin.sock`이 사라졌는지 확인한다.
3. 기존 `state.db`를 같은 filesystem의 `state.db.pre-restore`로 이동한다. 기존 파일을 덮어쓰지 않는다.
4. backup을 `/var/lib/pulse-agent/state.db`에 `pulse-agent:pulse-agent-admin`, mode `0600`으로 새로 설치한다.
5. 서비스를 시작한다. startup integrity/schema 검증과 `pulse-agent status`가 성공한 뒤에만 복구 완료로 판정한다.
6. 실패하면 서비스를 다시 중지하고 실패한 새 파일을 격리한 뒤 보존한 `state.db.pre-restore`를 원래 이름으로 되돌린다.

## Upgrade와 안전한 제거

업그레이드 전 backup과 digest를 확보하고 새 바이너리의 release digest를 검증한다. daemon을 중지하고 `/usr/local/bin/pulse-agent.new`에 먼저 설치한 뒤 원자적으로 기존 이름으로 이동하고 다시 시작한다. config validation과 status가 실패하면 이전 바이너리와 database backup으로 되돌린다.

제거할 때는 먼저 최종 backup을 만든 뒤 서비스를 중지·비활성화한다. unit, packaging 파일과 바이너리만 제거하고 `/etc/pulse-agent`, `/var/lib/pulse-agent`, backup, 전용 사용자/그룹은 기본적으로 보존한다. 데이터 폐기가 별도 승인되면 `/var/lib/pulse-agent`를 날짜가 포함된 격리 경로로 먼저 이동하고 보존 기간 후 삭제한다. 데이터가 남은 동안에는 UID/GID 재사용을 막기 위해 system account와 group을 제거하지 않는다.
