# Changelog

이 프로젝트의 사용자 영향 변경을 기록합니다.

## Unreleased

## 1.1.0 - 2026-09-02

### Added

- 분할된 입력을 먼저 전달하지 않고 완성한 뒤 검사하는 bounded `PromptStreamSession`을
  추가했습니다.
- 최근 대화의 관련 role을 하나의 공격 표면으로 유지하는 `ConversationGuardSession`을
  추가했습니다.
- 기본 출력에서 원문을 제외하고 check/context/messages를 제공하는 `ko-prompt-guard` CLI를
  추가했습니다.
- 간접 프롬프트 문서도 정규화 전에 입력 크기를 제한하고, 초과 시 원문을 보존하지 않은 채
  격리하도록 `scan_context()`의 fail-closed 경계를 보강했습니다.

### Documentation

- 공개 단계를 `Development Preview`로 재분류하고 PyPI maturity를 Beta로 맞췄습니다.
  공개 소스와 운영 효과 보증을 구분하고 권장 용도를 평가·통합과 Tier-1 다층 방어로 한정했습니다.
- 소프트웨어 안정성과 고객별 보안 효과를 분리하고, 제품을 포괄적 인젝션 판정기가 아닌
  한국어 난독 정규화·고신뢰 Tier-1으로 명확히 정의했습니다.
- 다른 제품의 데이터셋 한정 측정치와 규제 맥락을 범용 경쟁우위로 일반화하던 표현을
  제거했습니다.

## 1.0.0 - 2026-07-28

### Changed

- 모노레포의 `ko-prompt-guard/` 이력을 보존해 독립 저장소로 전환했습니다.
- 1.0 API 계약을 정하고 독립 CI와 통합 릴리스 증거에 연결했습니다.
- 독립 CI, 배포 경계, 보안 신고 및 기여 절차를 추가했습니다.
- `FLAG`를 `enforce()`에서 fail-closed 처리하고 단일·멀티턴 입력에 정규화 전 자원 상한과
  형식 검증을 적용했습니다.
- 원문, 정규화 텍스트 및 매칭 문자열을 제외한 운영 telemetry DTO를 추가했습니다.

### Removed

- 통합 저장소가 담당해야 하는 중복 3축 평가 스크립트와 서비스 Dockerfile을 제거했습니다.

## 0.2.0

- 한국어 난독 정규화, prompt injection, jailbreak, context scan 및 선택적 semantic reviewer
  인터페이스를 포함합니다.
- 이 버전은 독립 저장소의 첫 릴리스 후보이며 stable tag는 별도 승격 gate 통과 후 생성합니다.
