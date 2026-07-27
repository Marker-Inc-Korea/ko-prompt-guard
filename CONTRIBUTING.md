# Contributing

## Before You Start

동작 변경은 먼저 issue에서 위협 모델, 예상 판정과 한국어 과탐 영향을 합의해 주십시오. 보안 문제는
공개 issue 대신 [SECURITY.md](./SECURITY.md)의 비공개 절차를 사용합니다.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m mypy
python -m pytest
```

새 탐지 패턴에는 공격 변형과 어휘가 겹치는 정상 한국어 문장을 함께 추가해야 합니다. 코어
`check()` 경로의 결정론, 네트워크 독립성과 optional semantic reviewer 경계를 유지하십시오.

## Pull Requests

- 한 PR은 하나의 명확한 동작 변경에 집중합니다.
- 사용자 영향 변경은 `CHANGELOG.md`의 `Unreleased`에 기록합니다.
- 새 category, severity 또는 정규화 단계는 README와 공개 API 문서를 함께 갱신합니다.
- 생성물, 실제 고객 prompt, 자격증명과 비공개 평가 데이터는 커밋하지 않습니다.
- CI의 지원 Python 버전 테스트, ruff, mypy, pytest와 distribution build를 모두 통과합니다.
