# Pulse Agent

Pulse Agent는 Docker Engine이 실행되는 Linux 호스트에서 동작하는 Standalone 단일 바이너리 서비스다. 감시 대상 컨테이너 안에 설치하지 않으며, 클러스터 제어 기능이나 임의 host command 실행 기능을 제공하지 않는다.

## 빌드

Go 1.25 이상과 고정된 `go.sum`을 사용한다.

```text
make build-linux
make reproducible-linux
```

기본 결과는 `dist/pulse-agent-linux-amd64` 하나다. arm64 호스트는 `make build-linux GOARCH=arm64`를 사용한다. 빌드는 CGO를 끄고 VCS 경로와 linker build ID를 제거하므로 같은 Go toolchain, 소스, 모듈 캐시, `GOARCH`에서 두 결과가 바이트 단위로 같아야 한다.

## Linux 운영

systemd service, 전용 system account, 디렉터리 권한, 설정 예제는 [`packaging/`](packaging/)에 있다. 설치, 검증, target/runbook 등록, approval, status, backup/restore, upgrade와 제거 절차는 [`docs/operations.md`](docs/operations.md)를 따른다.

Docker socket 접근은 host root에 준하는 높은 로컬 권한이다. 서비스 계정과 바이너리, 설정 파일을 일반 애플리케이션 계정과 분리하고 관리 IPC를 최소 인원에게만 허용해야 한다.
