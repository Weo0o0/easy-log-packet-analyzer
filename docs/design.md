# easy-log-packet-analyzer 설계 문서

> 왜 필요한지: [why.md](why.md) · 핵심 기능: [features.md](features.md)

대상: 공부하는 취업 준비생. 몇 MB 크기의 공개 샘플 로그와 pcap을 웹 화면에서 보며 기초를 익히고 Wireshark로 넘어가게 돕습니다.
이 문서는 설계만 담습니다. 코드는 없습니다.

## 용어
- 파서: 글자나 바이트를 읽어 구조(필드)로 바꾸는 코드.
- 레코드: 로그 한 줄 또는 패킷 하나를 정리한 데이터 한 건.
- Streamlit: Python 코드만으로 웹 화면을 만드는 라이브러리.
- YAML: 사람이 읽기 쉬운 설정 파일 형식.

## 화면 기술 선택: Streamlit
- 이유: HTML/JavaScript 없이 Python만으로 표, 탭, 버튼을 만들 수 있어 Python을 조금 아는 사람에게 가장 쉬움.
- Flask는 화면을 HTML로 직접 만들어야 해서 배울 것이 더 많음. 나중에 필요하면 바꿈.

## 전체 구조
입력 → 파싱 → 해석(규칙) → 표시(웹)

레코드 공통 필드: 시간, 출발지, 목적지, 종류, 요약, 원본(근거로 보여 줄 줄/패킷 번호).

## 단계
### 1단계: 로그 파일 읽기 (3종)
- Linux `auth.log`: 정규식(글자 패턴 규칙)으로 시간, IP, 사용자, 성공/실패 추출.
- 웹 `access.log` (Apache/Nginx 기본 형식): 시간, IP, 요청 경로, 상태 코드.
- Windows 이벤트 로그(`.evtx`): `python-evtx` 라이브러리로 읽고 이벤트 ID(예: 4625 로그인 실패) 추출.
- 모두 레코드로 변환. 원본 줄 번호 보관.

### 2단계: pcap 읽기 (scapy)
- scapy로 패킷마다 시간, IP, 포트, 프로토콜, TCP 플래그를 레코드로 변환. 패킷 번호 보관(Wireshark 번호와 같게).
- 몇 MB만 처리. 큰 파일은 안내 문구 표시.

### 2-1단계: 대화(연결) 요약 만들기
- 패킷을 (IP, 포트, 프로토콜) 쌍으로 묶어 대화 레코드를 만듦. Zeek conn.log처럼 uid, 시작 시각, 지속 시간, 바이트 수, 상태, 흐름(history 비슷한 글자) 보관.
- 각 대화에 Wireshark `tcp.stream` / `udp.stream` 번호도 기록해 필터 번역에 사용.

### 3단계: 웹 화면 기본 (Streamlit)
- 파일 올리기, 로그 탭 / 패킷 탭 분리, 표로 보기. 대화 요약 탭 추가, 대화 한 줄을 누르면 패킷 탭에서 그 uid의 패킷 강조.
- 각 열과 필드에 "?" 도움 가이드 (설명은 `help.yaml`에 저장).

### 4단계: 시간 연결 보기
- 한쪽 탭에서 한 줄을 고르면 다른 탭에서 앞뒤 몇 초 범위를 강조.
- 시간대 차이(로그는 현지 시간, pcap은 UTC 등) 맞추는 설정 제공.

### 5단계: 필터와 Wireshark 명령 번역
- 클릭 필터(IP, 포트, 프로토콜, 시간)만 제공.
- 필터 조건마다 같은 뜻의 Wireshark 디스플레이 필터와 tshark 명령을 만들어 옆에 표시 (번역 표는 `filters.yaml`).

### 6단계: 규칙 파일 기반 경고와 오해 힌트
- `rules.yaml`: 경고 규칙. 각 규칙에 조건, 왜 이상한가, 다음 확인 단계, Wireshark 필터를 적음.
- 규칙 형식은 Zeek Notice를 참고: 종류(note), 메시지(msg), 대상(src), 숫자(n), 중복 억제 기준(identifier + 시간).
- "특이하지만 공격 아님"(Zeek Weird와 비슷)은 경고가 아니라 오해 힌트로 표시.
- `hints.yaml`: 초보 오해 힌트 (예: 재전송, RST, DNS 실패).
- 경고 카드에는 항상 근거(원본 줄/패킷)를 링크.
- AI 사용 안 함.

### 7단계 (선택): 공부 노트 내보내기
- 본 경고, 쓴 필터, 배운 용어를 마크다운으로 저장.

### 8단계 (선택, 나중): Zeek 로그 읽기
- Zeek가 만든 conn.log(TSV/JSON)를 4번째 로그 형식으로 읽어 대화 요약 탭에 표시. 간단할 때만.

## 하지 않을 것
- 실시간 캡처, 자동 차단, 대용량 처리, AI 설명, SIEM 연동.

## 샘플 데이터 (공개 자료만)
- Wireshark SampleCaptures: https://wiki.wireshark.org/SampleCaptures
- 로그 샘플: https://github.com/logpai/loghub
- 개인/회사 데이터는 넣지 않음.

## 참고
- [analysis/wireshark.md](analysis/wireshark.md)
- [analysis/zeek.md](analysis/zeek.md)
