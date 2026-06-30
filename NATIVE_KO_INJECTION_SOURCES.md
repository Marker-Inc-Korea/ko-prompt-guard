# native 한국어 인젝션 데이터 소스 (2026-06 발굴)

순수 native 한국어 *프롬프트 인젝션 전용* 라벨 데이터는 희소(4개 앵글 탐색 확인). 정리:

| 소스 | 건수 | native | 라이선스 | 비고 |
|---|---|---|---|---|
| **xxxjjhhh/korean_guardrail_test** (HF) | 647 | ✅ native | — | 현 학습/평가 메인. 인젝션 352/benign 295 |
| **prismdata/guardrail-ko-11class** (HF) | INJECTION 138K | ⚠️ MT-style(번역투) | GPL-3.0 | 대량이나 INJECTION은 영어셋 MT. SAFE/혐오는 native. 외부 일반화 평가용(v6 99.9%) |
| **boychaboy/RICoTA** (GitHub) | 609 | ✅ native | CC-BY-SA-4.0 | 이루다 챗봇 in-the-wild 레드팀(디시). 대화형이라 단일프롬프트 분류기엔 포맷 불일치 |
| **DAIOSFoundation/LLM-HACK** (GitHub) | ~20 | ✅ native | MIT | agent-misuse 스타일 합성. 소규모 |
| MultiJail ko (DAMO-NLP-SG) | 315 | MT(사람번역) | MIT | positive only, jailbreak |
| 과기정통부 레드팀 챌린지 2024 | 19,238 | ✅ native | 비공개 | 최대 규모이나 미공개(SelectStar 운영) |
| 숭실대 영어-한국어 탈옥셋 (논문) | 30만+ | MT | 미배포 | paper-only |

**결론**: v6(native+MT+합성)는 prismdata 3,000 외부셋에 99.9% 일반화 — 데이터 더 추가해도 수렴.
