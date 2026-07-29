# Changelog

이 프로젝트의 사용자 영향 변경을 기록합니다.

## Unreleased

### Documentation

- 소프트웨어 안정성과 고객별 보안 효과를 분리하고, 제품을 포괄적 인젝션 판정기가 아닌
  한국어 난독 정규화·고신뢰 Tier-1으로 명확히 정의했습니다.

## 1.0.0 - 2026-07-28

### Changed

- 모노레포의 `ko-prompt-guard/` 이력을 보존해 독립 저장소로 전환했습니다.
- 패키지 성숙도를 Production/Stable로 승격하고 독립 CI와 통합 릴리스 증거에 연결했습니다.
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
