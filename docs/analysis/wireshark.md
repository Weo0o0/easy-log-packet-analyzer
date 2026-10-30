# Wireshark / tshark 구조 분석 (입문자용)

근거: 공개 소스(GPL, https://gitlab.com/wireshark/wireshark)와 공식 문서(https://www.wireshark.org/docs/)만 사용했습니다. 확실하지 않은 부분은 "확인 못 함"으로 적었습니다.

## 용어 먼저
- 패킷: 네트워크로 오가는 데이터 한 덩어리.
- pcap / pcapng: 패킷을 저장하는 파일 형식. pcapng는 더 새로운 버전.
- libpcap(Windows는 Npcap): 네트워크 카드에서 패킷을 가져오는 라이브러리.
- 프로토콜: 데이터를 주고받는 약속(예: TCP, HTTP, DNS).
- 디섹터(dissector): 바이트를 읽어 "이 부분은 출발지 IP" 처럼 필드로 나누는 해석 함수.

## 전체 흐름
입력 → 파싱 → 해석 → 표시

### 1. 입력
- 실시간 캡처: `dumpcap` 프로그램이 libpcap으로 패킷을 받아 pcapng 파일로 씁니다. Wireshark/tshark는 이 파일을 읽습니다.
  - 소스: `dumpcap.c`, `capture/`
- 파일 읽기: `wiretap/` 라이브러리가 pcap, pcapng 등 여러 형식을 읽어 같은 형태의 "레코드"로 바꿉니다.
  - 소스: https://gitlab.com/wireshark/wireshark/-/tree/master/wiretap

### 2. 파싱 (epan = 패킷 분석 엔진)
- 디섹터: 프로토콜마다 하나씩 있습니다. 예: `epan/dissectors/packet-tcp.c`, `packet-http.c`.
- 프로토콜 트리: 디섹터가 찾은 필드를 트리(부모-자식 구조)로 쌓습니다. Ethernet 아래 IP, IP 아래 TCP 식입니다. 소스: `epan/proto.c`
- 디섹터 테이블(포트 기반): "TCP 포트 80이면 HTTP 디섹터를 불러라" 같은 표. 하위 프로토콜을 고르는 기본 방법입니다. 소스: `epan/packet.c` (`dissector_add_uint`)
- 휴리스틱 디섹터: 포트로 알 수 없을 때, 데이터 내용을 보고 "이 프로토콜 같다"고 추측하는 디섹터. 맞으면 처리, 아니면 다음 후보로 넘깁니다. (`heur_dissector_add`)
- 소스: https://gitlab.com/wireshark/wireshark/-/tree/master/epan
- 개발자 문서: https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html

### 3. 해석
- 디스플레이 필터: `ip.addr == 10.0.0.1 && tcp.port == 443` 같은 식으로 트리의 필드를 조건 검사해 패킷을 거릅니다. (캡처 필터(BPF)와 다름: 캡처 필터는 저장 전에 거름.) 소스: `epan/dfilter/`
  - 문서: https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html
- 전문가 정보(Expert Info): 디섹터가 "재전송", "잘못된 체크섬" 같은 이상을 경고 등급과 함께 표시. 소스: `epan/expert.c`
- 스트림 재조립: TCP로 잘려 온 데이터를 순서대로 이어 붙여 HTTP 요청 하나처럼 완전한 메시지로 만듭니다. 소스: `epan/reassemble.c`, `packet-tcp.c`
- Follow Stream: 한 연결(출발지/목적지 IP·포트 쌍)의 데이터만 이어서 보여주는 기능. 소스: `epan/follow.c`
- 통계: 대화(Conversations), 엔드포인트, 프로토콜 계층 통계, I/O 그래프 등. tshark에서는 `-z` 옵션. 소스: `ui/` 의 tap 관련 파일 ("tap" = 디섹터 결과를 통계 모듈로 넘기는 통로)

### 4. 표시
- GUI 3분할 화면 (Qt, 소스 `ui/qt/`):
  1. 패킷 목록: 한 줄에 패킷 하나 (시간, 출발지, 목적지, 프로토콜, 요약)
  2. 패킷 상세: 프로토콜 트리
  3. 패킷 바이트: 원본 16진수
- tshark(명령줄 버전, 소스 `tshark.c`) 출력:
  - 기본 텍스트 한 줄 요약
  - `-V` 상세 트리
  - `-T json` / `-T ek` JSON
  - `-T fields -e ip.src -e ip.dst` 원하는 필드만 표 형태
  - 문서: https://www.wireshark.org/docs/man-pages/tshark.html

## 우리 도구에 가져갈 것
- 입력 → 파싱 → 해석 → 표시 4단계 구조 그대로 사용 (로그와 패킷 모두)
- 필드 이름으로 거르는 필터 (단, 문법은 아주 단순하게)
- 전문가 정보처럼 "이상한 점"을 쉬운 문장으로 경고
- 대화/상위 IP 같은 기본 통계
- tshark `-T fields`/JSON처럼 기계가 읽기 쉬운 출력
- 프로토콜 해석은 직접 만들지 않고 scapy 또는 tshark(pyshark)에 맡김

## 버릴 것
- 3000개 넘는 디섹터 직접 구현
- 실시간 캡처 (권한·드라이버 문제, 초기에는 파일만)
- 복잡한 GUI 3분할 화면, 플러그인 시스템, Lua 스크립트
- 휴리스틱 디섹터 직접 구현
- 완전한 디스플레이 필터 문법

## 확인 못 함
- tap 처리는 `epan/tap.c`에 있음을 확인함. 각 통계 기능이 어느 파일에 있는지는 전부 확인 못 함.
- 링크 확인: 이 문서의 모든 링크가 2026-10-30에 열림(HTTP 200).
