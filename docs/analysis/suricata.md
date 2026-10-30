# Suricata 구조 분석 (입문자용)

근거: 공개 소스(GPLv2, https://github.com/OISF/suricata)와 공식 문서(https://docs.suricata.io)만 사용. 이번에 직접 열어 본 페이지만 출처로 적었고, 열지 못한 부분은 "확인 못 함"으로 표시했습니다. 공격 방법이나 탐지 회피 내용은 다루지 않습니다.

## 용어
- Suricata: 네트워크 트래픽을 규칙(룰)과 비교해 경보를 만드는 침입 탐지 도구(IDS). 설정에 따라 차단(IPS)도 함.
- IDS / IPS: 탐지만 하는 시스템 / 탐지하고 막기까지 하는 시스템.
- 룰(시그니처): "이런 트래픽이면 경보"를 한 줄로 적은 규칙.
- 디코더: 패킷 바이트를 Ethernet, IP, TCP 같은 층별로 나누는 코드.
- 스트림 재조립: 여러 TCP 패킷을 순서대로 이어 붙여 원래 데이터로 만드는 것.
- 앱 레이어 파서: HTTP, DNS 같은 응용 프로토콜을 해석하는 코드.
- flow: Suricata에서 "연결"을 부르는 말. Zeek의 connection과 비슷.

## 전체 흐름
입력 → 파싱 → 해석(룰 엔진) → 표시(로그)

### 1. 입력
- 파일 모드: `-r <경로>` = pcap 파일을 읽는 오프라인 모드. 폴더를 주면 수정 시간 순서로 모든 파일을 처리.
- 실시간: `-i <장치>`(가능한 가장 좋은 방식 자동 선택), `--pcap`, `--af-packet`(리눅스), `--af-xdp`, `--netmap`, `--pfring` 등.
- 룰 파일 지정: `-s`(설정에 더해 읽기), `-S`(이 파일만 읽기). 로그 폴더: `-l`.
- 출처: https://docs.suricata.io/en/latest/command-line-options.html

### 2. 파싱
- 디코더, 스트림 재조립, 앱 레이어 파서, 프로토콜 탐지(포트가 아니라 내용으로 프로토콜 판단)가 있다는 점은 문서 곳곳에서 확인됨:
  - 룰의 프로토콜 칸에 `tcp-pkt`(패킷 하나씩) / `tcp-stream`(재조립된 스트림)을 고를 수 있음.
  - `http`로 적은 룰은 "TCP 스트림이 실제로 HTTP일 때만" 맞음 → 포트가 아닌 내용 기반 판단.
  - eve.json의 anomaly 이벤트 `type`이 `decode`(디코더) / `stream`(스트림) / `applayer`(앱 레이어) 셋이고, applayer는 `proto_parser`(파서) / `proto_detect`(프로토콜 탐지)로 나뉨.
  - 출처: https://docs.suricata.io/en/latest/rules/intro.html , https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- 각 단계의 소스 파일 위치와 내부 동작: 확인 못 함.

### 3. 해석 (룰 엔진)
룰은 세 부분: 동작(action) + 헤더(header) + 옵션(options).

공식 문서 예:
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
- 동작: `alert`(경보), `pass`(더 검사 안 함), `drop`(버리고 경보, IPS), `reject` 계열(연결 끊기 신호 보냄).
- 헤더: 프로토콜, 출발지 IP/포트, 방향(`->` 한 방향, `<>` 양방향), 목적지 IP/포트. `$HOME_NET`(우리 네트워크) 같은 변수는 suricata.yaml에서 정함.
- 옵션 (괄호 안, `;`로 구분, 순서가 의미를 바꿈):
  - `msg`: 경보에 보일 설명
  - `content`: 찾을 바이트/글자
  - `flow`: 연결 상태·방향 (예: `established,to_server`)
  - `sid`: 룰 고유 번호, `rev`: 룰 버전
  - `classtype`: 경보 분류
  - `fast_pattern`: 먼저 빠르게 찾을 글자 지정
- 빈도 조절:
  - `threshold`: `type threshold`(N번째에 경보), `limit`(시간당 최대 N번), `both`, `backoff`. `track by_src/by_dst/by_both/by_rule/by_flow`, `count`, `seconds`.
  - `detection_filter`: N번 넘은 뒤부터 매번 경보. `unique_on dst_port`로 서로 다른 포트 수를 셀 수 있음 (문서 예: 60초 안에 서로 다른 목적지 포트 10개 이상 → 스캔 의심 `classtype:attempted-recon`).
  - 출처: https://docs.suricata.io/en/latest/rules/thresholding.html
- 다중 패턴 매칭(MPM, 많은 룰의 글자를 한 번에 찾는 방식)의 내부 구조: 확인 못 함 (`fast_pattern` 존재만 확인).

### 4. 표시 (로그)
- eve.json: 한 줄에 JSON 이벤트 하나. 공통 필드 `timestamp`, `flow_id`, `event_type`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `app_proto`.
  - `event_type` 예: `alert`, `flow`, `http`, `dns`, `tls`, `fileinfo`, `anomaly` 등.
  - `alert` 안: `signature_id`(룰의 sid), `rev`, `signature`(룰의 msg), `category`, `severity`, `action`(`allowed`/`blocked`).
  - `flow_id`: 같은 연결의 alert/http/flow 이벤트를 묶는 ID (Zeek uid와 같은 역할).
  - `pcap_cnt`: pcap 모드일 때 패킷 번호. 문서에 "Wireshark에서 그 패킷을 찾는 데 쓸 수 있다"고 나옴.
  - 출처: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- fast.log(한 줄 요약 경보 로그) 형식: 확인 못 함.

## Wireshark, Zeek와 짧은 비교
| | Wireshark | Zeek | Suricata |
|---|---|---|---|
| 보는 단위 | 패킷 | 연결 요약 | 룰에 맞은 이벤트(+연결 요약) |
| 핵심 | 깊은 해석 화면 | 로그 + 스크립트 | 룰 매칭 경보 |
| 연결 묶는 ID | `tcp.stream` | `uid` | `flow_id` |
| 결과 | GUI, tshark 출력 | TSV/JSON 로그 | eve.json |

## 우리 도구에 가져갈 것
- 룰 칸 이름: `msg`, `sid`(고유 번호)+`rev`(버전), `classtype`(분류) → 쉬운 한국어로
- `threshold`/`detection_filter`처럼 "누구 기준(track), 몇 번(count), 몇 초(seconds)"로 세는 방식
- `unique_on`처럼 "서로 다른 포트 개수 세기"(스캔 의심 규칙에 사용)
- `pcap_cnt`처럼 경보마다 패킷 번호를 남겨 Wireshark에서 바로 찾기
- 경고 카드에 "Suricata로 쓰면 이런 룰" 텍스트를 읽기 전용으로 보여 주기 (학습용)

## 버릴 것
- 실제 룰 엔진, 차단(IPS, drop/reject), 실시간 캡처, 대량 룰셋, 성능 설정(runmode 등)
