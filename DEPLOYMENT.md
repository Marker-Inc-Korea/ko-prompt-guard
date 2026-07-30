# ko-prompt-guard Deployment

`ko-prompt-guard`는 현재 **Development Preview**다. 아래 계약은 평가 환경과 배포 후보에서
재현 가능하게 검증하기 위한 기준이며, 고객 환경의 탐지 효과나 단독 운영 적합성을 보증하지 않는다.

이 저장소는 `ko-prompt-guard` 패키지, 공개 정책 API와 제품 테스트의 canonical source다. 인증,
감사, 공통 정책 로더와 컨테이너 hardening을 포함한 HTTP 서비스 조립은
[`modak_experiments/deployment`](https://github.com/Marker-Inc-Korea/modak_experiments/tree/main/deployment)
에서 관리한다. 공용 런타임을 제품별로 복제하지 않기 위해 이 저장소에는 서비스 `Dockerfile`을 두지 않는다.

## Package Qualification

```bash
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m mypy
python -m pytest
python -m build --sdist --wheel
```

릴리스 후보는 이 저장소의 clean commit에서 만들어야 하며, wheel 검증과 Python 지원 버전 CI가 모두
통과해야 한다. 패키지 검증은 HTTP 서비스 승격을 대신하지 않는다.

## Service Contract

- `GET /health/live`: 프로세스 생존 확인
- `GET /health/ready`: 최소 ready/not-ready 상태
- `GET /v1/metadata`: Bearer 인증 필요
- `POST /v1/check`: Bearer 인증 필요

입력 검사는 `{"text":"...", "mode":"input"}`, 간접 인젝션 검사는
`{"text":"...", "mode":"context", "source":"rag"}` 형식이다. 응답과 감사 로그에는 원문 대신
요청 길이와 HMAC-SHA256만 남는다.

상세 정책·provenance·canary 결과는 인증된 `/v1/metadata` 또는 `--check`에서만 반환한다.

결정론 서비스는 사용자 입력과 RAG/도구 컨텍스트를 분리해 검사한다. 선택 ML reviewer는 이
프로세스에 로드하지 않는다. 모델 reviewer는 별도의 Slurm GPU endpoint로 배포·검증해야 한다.
통합 저장소는 이미지에 이 저장소의 exact commit을 기록하고, source digest, SBOM, signature,
preflight와 `ko-redteam` 증거 gate를 함께 검증해야 한다.
