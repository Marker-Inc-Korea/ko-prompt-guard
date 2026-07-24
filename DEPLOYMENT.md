# ko-prompt-guard Deployment

배포 이미지는 사용자 입력과 RAG/도구 컨텍스트를 분리해 검사하는 결정론 서비스다. 선택 ML
reviewer는 이 프로세스에 로드하지 않는다. `KO_INJ_CLF_DIR` 또는 `KO_CTX_CLF_DIR`가 설정되면
readiness가 실패하며, 모델 reviewer는 별도의 Slurm GPU endpoint로 배포·검증해야 한다.

## Build

저장소 루트에서 immutable source commit을 넣어 빌드한다.

```bash
docker build -f ko-prompt-guard/Dockerfile \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t ko-prompt-guard:0.2.0 .
```

## Run

```bash
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8081:8080 \
  -e KO_GUARD_API_TOKEN="$KO_GUARD_API_TOKEN" \
  -e KO_GUARD_AUDIT_HMAC_KEY="$KO_GUARD_AUDIT_HMAC_KEY" \
  -v "$PWD/deployment/policies/prompt-production.json:/run/policy.json:ro" \
  -e KO_GUARD_POLICY_FILE=/run/policy.json \
  ko-prompt-guard:0.2.0
```

`KO_GUARD_API_TOKEN`과 `KO_GUARD_AUDIT_HMAC_KEY`는 각각 최소 32바이트여야 한다. 외부 bind에서
둘 중 하나라도 없으면 기동을 거부하며, 두 값은 서로 다른 secret으로 발급한다.

## API

- `GET /health/live`: 프로세스 생존 확인
- `GET /health/ready`: 최소 ready/not-ready 상태
- `GET /v1/metadata`: Bearer 인증 필요
- `POST /v1/check`: Bearer 인증 필요

입력 검사는 `{"text":"...", "mode":"input"}`, 간접 인젝션 검사는
`{"text":"...", "mode":"context", "source":"rag"}` 형식이다. 응답과 감사 로그에는 원문 대신
요청 길이와 HMAC-SHA256만 남는다.

상세 정책·provenance·canary 결과는 인증된 `/v1/metadata` 또는 `--check`에서만 반환한다.

배포 승격은 [suite deployment contract](../deployment/README.md)의 이미지 digest, SBOM,
preflight와 `ko-redteam` 증거 gate를 모두 통과해야 한다.
