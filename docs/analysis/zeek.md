# Zeek 구조 분석 (입문자용)

근거: 공개 소스(BSD 라이선스, https://github.com/zeek/zeek)와 공식 문서(https://docs.zeek.org)만 사용. 이번에 직접 열어 본 페이지만 출처로 적었고, 열지 못한 부분은 "확인 못 함"으로 표시했습니다. (docs.zeek.org 일부 페이지는 접속 제한으로 열지 못함)

## 용어
- Zeek: 네트워크 트래픽을 읽어 "무슨 일이 있었는지"를 로그 파일로 남기는 분석 도구 (예전 이름 Bro).
- 연결(connection): 두 컴퓨터가 주고받은 패킷 묶음 하나. TCP뿐 아니라 UDP도 Zeek는 연결로 봄.
- originator / responder: 연결을 먼저 시작한 쪽 / 응답한 쪽.
- 이벤트: "HTTP 요청이 왔다" 같은 사건 알림. Zeek 스크립트가 이것을 받아 처리.
- 분석기(analyzer): 특정 프로토콜(HTTP, DNS 등)을 해석하는 Zeek 내부 코드.
- uid: Zeek가 연결마다 붙이는 고유 ID. 여러 로그에서 같은 연결을 찾는 데 사용.

## 전체 흐름
입력 → 파싱 → 해석 → 표시

### 1. 입력
- 저장된 pcap 파일 읽기(`zeek -r 파일.pcap`) 또는 네트워크 장치 실시간 감시. conn.log 문서에 "라이브 인터페이스 또는 저장된 트래픽" 둘 다 가능하다고 나옴.
  - 출처: https://docs.zeek.org/en/master/logs/conn.html
- 실시간 캡처에 libpcap / AF_PACKET(리눅스 커널의 빠른 패킷 수신 방식)을 쓰는 세부 구조: 확인 못 함.

### 2. 파싱
- 이벤트 엔진: 패킷을 연결 단위로 모으고, 프로토콜 분석기가 해석한 결과를 이벤트로 만들어 스크립트 쪽에 넘김. (구조 설명 페이지는 열지 못해 세부는 확인 못 함)
- 프로토콜 분석기 소스: https://github.com/zeek/zeek/tree/master/src/analyzer/protocol
- 동적 프로토콜 탐지(DPD): 포트가 아니라 데이터 내용으로 프로토콜을 알아내는 기능. 시그니처가 맞으면 `enable "http"` 같은 동작으로 해당 분석기를 켬. 기본으로 각 TCP 연결의 처음 1KB 정도만 검사.
- 시그니처: Snort 스타일의 패턴 규칙 (예: TCP 80번 포트에서 payload에 `root`가 있으면 이벤트). Zeek는 시그니처보다 스크립트를 주된 탐지 방법으로 씀.
  - 출처: https://docs.zeek.org/en/master/frameworks/signatures.html

### 3. 해석
- Zeek 스크립트: 이벤트를 받아 로그를 쓰고 탐지 판단을 하는 Zeek 전용 언어. (문법 세부 확인 못 함)
- Notice 프레임워크: 스크립트는 "이상할 수 있음"만 `NOTICE`로 표시하고, 실제로 기록·메일·무시할지는 각 사이트 설정(`Notice::policy`)이 정함. "공격의 기준은 환경마다 다르다"는 이유.
  - notice 주요 필드: `note`(종류, 예: `SSH::Password_Guessing`), `msg`(사람이 읽는 설명), `src`(대상 IP), `n`(숫자), `identifier`(같은 notice 중복 억제용).
  - 같은 `note` + `identifier`는 일정 시간 다시 띄우지 않음(자동 억제).
  - Weird 로그: "이상하지만 보통 보안 사건은 아닌 것"(예: TCP 상태 위반)을 따로 기록. 공식 문서도 "바로 탐지로 보지 말라"고 설명.
  - 출처: https://docs.zeek.org/en/master/frameworks/notice.html
- Intel 프레임워크(위협 정보 목록과 대조): 확인 못 함.

### 4. 표시 (로그)
- 결과는 TSV(탭으로 구분한 표) 또는 JSON 로그 파일. notice.log 예시는 TSV, conn.log 문서 예시는 JSON.
- conn.log: 연결 하나당 한 줄. "누가 누구와, 언제, 얼마나 오래, 어떤 프로토콜로". 주요 필드:
  - `ts`(시작 시각), `uid`, `id.orig_h`/`id.orig_p`(시작한 쪽 IP/포트), `id.resp_h`/`id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`/`resp_bytes`, `conn_state`, `history`
  - `conn_state` 예: `SF` = 정상적으로 시작하고 정상 종료.
  - `history` 예: `ShADadFf` = 대문자는 시작한 쪽, 소문자는 응답한 쪽 동작 (S=SYN, h=SYN-ACK, A=ACK, D/d=데이터, F/f=FIN).
  - 공식 문서도 같은 연결을 tshark로 열어 바이트 수를 대조함.
- uid로 연결: conn.log의 uid로 http.log, dns.log 등 다른 로그에서 같은 연결을 찾음.
- http.log, dns.log, ssl.log 필드 세부: 확인 못 함 (페이지 열지 못함).
- zeek-cut(로그에서 원하는 열만 뽑는 명령): 확인함.
  - 위치: 예전에는 zeek-aux 저장소에 있었으나, zeek-aux CHANGES(2026-03-02)에 "zeek-cut은 zeek 저장소로 옮김"이라고 적혀 있고, 현재 소스는 zeek 저장소 `tools/zeek-cut/`에 있음.
  - 하는 일: 표준 입력으로 받은 ASCII(TSV) Zeek 로그에서 지정한 열만 출력. 열 이름은 로그 맨 위 `#fields` 줄에 있음. 열 이름을 안 주면 전부 출력. 적은 순서대로 출력하므로 열 순서도 바꿀 수 있음.
  - 맨 위 `#`로 시작하는 형식 헤더 줄이 있어야 동작. JSON 로그는 지원 안 함. 압축 로그는 `zcat`으로 풀어서 넘김.
  - 주요 옵션: `-d` 시간을 읽기 쉬운 형식으로(현지 시간), `-u` 같은 변환을 UTC로, `-D`/`-U <형식>` 시간 형식 직접 지정, `-c` 첫 헤더 블록 포함, `-C` 모든 헤더 포함, `-m`/`-M` 헤더를 열 이름만 간단히, `-n` 지정한 열을 빼고 출력, `-F` 출력 구분 문자 변경.
  - 예: `cat conn.log | zeek-cut -d ts id.orig_h id.orig_p`
  - 출처: https://github.com/zeek/zeek/blob/master/tools/zeek-cut/README.md , https://github.com/zeek/zeek/blob/master/tools/zeek-cut/zeek-cut.1 , https://github.com/zeek/zeek-aux/blob/master/CHANGES


## Wireshark와 비교
| | Wireshark | Zeek |
|---|---|---|
| 보는 단위 | 패킷 하나씩 | 연결(대화) 하나씩 요약 |
| 결과 | 화면 트리, tshark 출력 | 로그 파일(conn.log 등) |
| 강점 | 바이트 수준 깊은 해석 | 많은 트래픽을 짧게 요약, 로그 간 uid 연결 |
| 탐지 | Expert Info(프로토콜 이상) | 스크립트 + Notice |
| 입문자에게 | 정보가 너무 많음 | 설치·스크립트 지식 필요 |

## 우리 도구에 가져갈 것
- 패킷을 연결 단위로 묶은 "대화 요약" 보기 (conn.log처럼 uid, 시작 시각, 양쪽 IP/포트, 지속 시간, 바이트, 상태)
- `history` / `conn_state`를 쉬운 한국어로 풀어 주기
- uid로 대화 요약 ↔ 패킷 연결
- Notice처럼 "종류·메시지·대상·중복 억제 기준"이 있는 경고 규칙 형식
- Weird처럼 "특이하지만 공격 아님" 구분 → 기존 "오해 주의" 힌트와 연결

## 버릴 것
- Zeek 스크립트 언어, 클러스터, 메일 알림, Intel 피드, 시그니처 엔진, 실시간 감시
- 수십 종의 프로토콜 로그 직접 구현
