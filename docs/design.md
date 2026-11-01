# easy-log-packet-analyzer 설계 문서

> **1~4단계 구현 완료(main), 5~11단계 상세 설계 (2026-10-30).** 다음: 5단계 구현. 1단계부터 차례대로 만들고, 단계마다 아래 '완료 확인 방법'으로 확인합니다.

> 왜 필요한지: [why.md](why.md) · 핵심 기능: [features.md](features.md) · 샘플: [samples.md](samples.md)

대상: 공부하는 취업 준비생. 몇 MB 크기의 공개 샘플 로그와 pcap을 웹 화면에서 보며 기초를 익히고 Wireshark로 넘어가게 돕습니다.
이 문서는 설계만 담습니다. 코드는 없습니다.

## 라이브러리와 환경
- Python 3.11 이상에서 동작합니다.
- 저장소 라이선스는 MIT로 유지합니다. Streamlit 1.66.1은 Apache-2.0 라이선스입니다.
- `requirements` 라이브러리 목록에 Streamlit 1.66.1을 둡니다.
- pcap 읽기에는 dpkt(BSD 라이선스)를 씁니다. BSD는 MIT와 같은 허용적(permissive) 라이선스라 함께 써도 됩니다.
- dpkt: pcap·pcapng 파일을 읽어 패킷을 계층(이더넷, IP, TCP 등)으로 나눠 주는 Python 라이브러리.
- pcapng: PR #13에서 `dpkt.pcapng.Reader`로 읽기를 추가했습니다(파일 앞 4바이트가 pcapng 표시 `0A 0D 0D 0A`이면 pcapng로 읽음). 코더 에이전트 보고: dns.cap을 pcapng로 바꾼 사본에서 확인. 코드에서도 확인함: `tests/test_step2_acceptance.py`가 dns.cap을 `dpkt.pcapng.Writer`로 바꿔 38개 레코드와 대화 결과가 pcap과 같은지 검사하고 통과(2026-10-30, Mac mini). Wireshark/editcap으로 만든 pcapng, 여러 인터페이스가 섞인 pcapng는 확인 못 함.

## 용어
- 파서: 글자나 바이트를 읽어 구조(필드)로 바꾸는 코드.
- 레코드: 로그 한 줄 또는 패킷 하나를 정리한 데이터 한 건.
- 정규식(regex): 글자 패턴 규칙. 괄호 `( )`로 잡은 부분이 값이 됩니다.
- Streamlit: Python 코드만으로 웹 화면을 만드는 라이브러리.
- YAML: 사람이 읽기 쉬운 설정 파일 형식.

## 화면 기술 선택: Streamlit
- 이유: HTML/JavaScript 없이 Python만으로 표, 탭, 버튼을 만들 수 있어 Python을 조금 아는 사람에게 가장 쉬움.
- Flask는 화면을 HTML로 직접 만들어야 해서 배울 것이 더 많음. 나중에 필요하면 바꿈.

## 전체 구조
입력 → 파싱 → 해석(규칙) → 표시(웹)

레코드 공통 필드: 시간, 출발지, 목적지, 종류, 요약, 원본(근거로 보여 줄 줄/패킷 번호).

설정 파일:
| 파일 | 내용 | 참고한 도구 |
|---|---|---|
| `decoders.yaml` | 로그 종류별 정규식과 필드 이름 | Wazuh 디코더 |
| `help.yaml` | 열·필드 "?" 설명과 상태 코드의 한 줄 설명 | - |
| `filters.yaml` | 필터·열 이름 → Wireshark/tshark/zeek-cut/awk 번역 | Wireshark, Zeek |
| `rules.yaml` | 경고 규칙 | Zeek Notice, Suricata, Sigma, Wazuh |
| `hints.yaml` | 초보 오해 힌트 | Zeek Weird |
| `layers.yaml` | 계층·로그 종류 이름과 한 줄 설명 (7.5단계) | - |
| `learning.yaml` | 시나리오 학습 카드 (8.5단계, 공부용) | - |
| `scenarios.yaml` | 기록이 보이는 흔한 상황 예시 (7.5단계, 방어·공부용) | - |

## 단계
샘플 이름은 [samples.md](samples.md)에 있는 것입니다.

### 1단계: 로그 파일 읽기 (3종)
- 목표: 로그 3종을 레코드로 바꾼다.
- 입력: `auth.log`(sshd 줄), Apache/Nginx `access.log`, Windows `.evtx`.
- 출력: 레코드 목록(원본 줄 번호 포함). 정규식에 안 맞는 줄은 "읽지 못한 줄"로 세어 표시.
- 읽지 못한 줄 번호: PR #14에서 `ParseResult.unparsed_lines`(줄 번호 목록, 최대 1,000개)와 `unparsed_lines_truncated`(1,000개를 넘어 잘렸는지)를 추가했습니다. `.evtx`는 줄 대신 이벤트 레코드 번호를 넣습니다. pcap은 패킷 단위로 읽어 "읽지 못한 줄"이 없고 `unparsed=0`이며, 잘린 경우는 `notices` 안내로 알립니다.
- 방법: 텍스트 로그는 `decoders.yaml`의 표를 씁니다. Wazuh 디코더처럼 `prematch`(이 줄이 맞는지 먼저 확인) → `regex`(값 잡기) → `fields`(잡은 값에 차례대로 이름 붙이기) 순서입니다. `.evtx`는 `python-evtx`로 읽고 EventID, 시간, IpAddress, TargetUserName을 뽑습니다.
- `decoders.yaml` 모양(설계 예시):
  | 로그 종류 | prematch | regex (요지) | fields |
  |---|---|---|---|
  | sshd 실패 | `Failed password for` | `for (invalid user )?(.+?) from (\S+) port (\d+)` | `invalid`, `user`, `srcip`, `srcport` |
  | sshd 성공 | `Accepted password for` | `for (\S+) from (\S+) port (\d+)` | `user`, `srcip`, `srcport` |
  | sshd 없는 사용자 | `Invalid user` | `Invalid user (\S*) from (\S+)` | `user`, `srcip` |
  | `sshd_other` (나머지 sshd) | (앞의 3개에 안 걸린 sshd 줄) | `^(.*)$` | `message` |
  | access.log | (없음, 모든 줄) | `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+)` | `srcip`, `time`, `method`, `path`, `status`, `bytes` |
  - 사용자 이름 앞에 공백이 한 칸 더 있는 줄이 있어서(예: `invalid user  0101`) 사용자 칸은 `\S+`가 아니라 최소 한 글자인 `(.+?)`로 잡습니다.
  - 줄 앞의 시간·호스트·프로그램 이름(`Dec 10 06:55:48 LabSZ sshd[24200]:`)은 공통 앞부분 정규식 하나로 먼저 잘라 냅니다.
  - 앞의 3개 규칙(실패·성공·없는 사용자)에 안 맞은 나머지 sshd 줄은 4번째 규칙 `sshd_other`로 잡아 OpenSSH_2k.log 2,000줄이 모두 레코드가 되게 합니다. 경고 규칙에는 앞의 3종 이벤트만 씁니다.
- 완료 확인 방법: OpenSSH_2k.log → 레코드 2,000건, 그중 "sshd 실패" 520건. apache_logs → 10,000건, `status=404` 213건. security.evtx → EventID 4624가 583건. 숫자는 `grep -c`, `awk`로 센 값과 같아야 합니다.
- 기능: 3번(로그/패킷 분리), 8번(열 고르기)의 바탕.

### 2단계: pcap 읽기 (dpkt)
- 목표: 패킷을 레코드로 바꾼다. 분석: [analysis/scapy.md](analysis/scapy.md).
- 입력: pcap/pcapng 파일. 크기 제한 10MB(설계 값, 구현 때 dns.cap보다 큰 공개 샘플로 속도를 재고 조정).
- 방법: `dpkt.pcap.Reader`(pcap) 또는 `dpkt.pcapng.Reader`(pcapng)로 한 개씩 읽음(파일 전체를 메모리에 올리지 않음). `dpkt.ethernet.Ethernet(buf)`로 이더넷부터 계층을 차례로 해석. 읽는 순서대로 1부터 번호를 붙여 Wireshark `frame.number`와 맞춤.
- 레코드 필드 대응:
  | 우리 필드 | dpkt에서 | 없으면 |
  |---|---|---|
  | 번호 | 읽은 순서(1부터) | - |
  | 시간 | `ts` (UTC 초) → 날짜·시각으로 바꿈 | - |
  | 출발지/목적지 | `dpkt.ethernet.Ethernet(buf)`를 풀어 IP/IPv6의 `src`/`dst` | 빈칸 |
  | 포트 | TCP/UDP의 `sport`, `dport` | 빈칸 |
  | 전송 계층(`transport`) | IP 안쪽 객체 타입 확인(`isinstance(..., dpkt.tcp.TCP)` / `dpkt.udp.UDP`) → `"TCP"` / `"UDP"` / `"other"` (요약 문자열로 판단하지 않음) | `"other"` |
  | 종류(`protocol`) | 가장 안쪽 응용 계층 이름 (예: `"DNS"`) | Raw |
  | TCP 플래그 | TCP `flags` | 빈칸 |
  | 길이 | `len(buf)` | - |
  | 요약 | 계층 이름으로 우리가 만든 한 줄 요약 | - |
  | 원본 | 번호 (상세 보기에서 패킷 필드와 원본 값) | - |
- 오류 처리:
  - pcap이 아닌 파일(`ValueError`) → "pcap 파일이 아닙니다" 안내, 아무것도 표시 안 함.
  - 잘린 파일(`dpkt.dpkt.NeedData`, `dpkt.dpkt.UnpackError`) → 읽은 만큼 표시하고 "파일 끝이 잘려 N개까지만 읽음" 안내.
  - 모르는 링크 타입 → Raw로 읽고 안내.
  - 10MB 초과 → 읽지 않고 안내.
- 완료 확인 방법: dns.cap → 패킷 38개, 모두 종류 DNS, UDP 53번 포트 38개, 1번 요약 `Ethernet / IP / UDP / DNS`, 1번 시간 1112172466.496046(UTC 초). 이 숫자들은 dpkt로 확인했습니다. 앞 500바이트만 남긴 dns.cap 사본 → 4개 + 잘림 안내. 텍스트 파일 → 오류 안내. (tshark 비교는 tshark 설치 후)
- 기능: 3번, 2번.

### 3단계: 대화(연결) 요약 만들기
- 목표: 패킷을 대화로 묶는다.
- 입력: 2단계 패킷 레코드.
- 방법: dpkt에는 Scapy `sessions()` 같은 대화 묶기 기능이 없어서 직접 만듦. TCP/UDP 구분은 패킷 레코드의 `transport` 필드로 판단함. 양방향 패킷이 하나로 묶이도록 내부 묶음 키는 `(transport, 정렬한 (IP, 포트) 쌍)`을 씀.
- 대화 레코드 형식:
  - `uid`: `"tcp-N"` / `"udp-N"`. 전송 계층(`transport`)별로 따로 0부터 첫 패킷이 나온 순서대로 번호를 붙임(Wireshark `tcp.stream` / `udp.stream` 번호 매기는 방식과 맞춤. tshark로 실제 비교는 확인 못 함, 구현 때 확인).
  - `protocol`: 전송 계층 이름(`"TCP"` / `"UDP"`).
  - `service`: 첫 패킷의 응용 계층 이름(예: `"DNS"`). Zeek `conn.log`의 `service` 열과 같은 역할.
  - `a`, `b`: `a`는 대화를 먼저 시작한 쪽(originator, 첫 패킷의 출발지), `b`는 응답한 쪽(responder, 첫 패킷의 목적지). 내부 키는 양방향 매칭을 위해 `(IP, 포트)` 쌍을 정렬해 쓰지만, 화면과 레코드의 `a`/`b` 순서는 문자열 정렬이 아니라 첫 패킷 기준(문자열 정렬은 클라이언트가 응답자 자리에 갈 수 있어 초보자에게 헷갈리므로 버림, Zeek orig/resp 방식과 같음).
  - `start`: 시간대 정보가 붙은(tz-aware) UTC 기준 ISO 8601 문자열(예: `2005-03-30T02:47:46.946Z` 형태). 화면 표시 때 현지 시간으로 바꿈.
  - `history`: Zeek 방식 흐름 문자열. 대문자는 `a`(시작한 쪽), 소문자는 `b`(응답한 쪽). TCP는 Zeek처럼 `S`, `H`(SYN-ACK), `A`, `D`, `F`, `R` 글자를 쓰고, UDP는 방향별 데이터 유무만 `D`/`d`로 적음(예: 요청+응답이면 `"Dd"`).
  - `state`: 코드 값만 넣음(한국어 설명은 필드에 넣지 않고 `hints.yaml`/`help.yaml`에 둠). TCP는 Zeek `conn_state` 일부(`S0`, `SF`, `REJ`, `RSTO`, `RSTR`, `OTH`), UDP는 양방향 모두 보이면 `SF`, 한쪽만 보이면 `S0`.
  - 그 외: 지속 시간, 패킷 수, 바이트 수.
- 범위: TCP 재조립은 하지 않음(dpkt는 TCP 재조립을 기본으로 하지 않음).
- 완료 확인 방법: dns.cap → 대화 8개(모두 `protocol="UDP"`, `service="DNS"`), 가장 큰 대화 192.168.170.8:32795 ↔ 192.168.170.20:53 = 24패킷. 이 숫자들은 dpkt로 확인했습니다. 대화별 실제 `state`/`history` 값은 확인 못 함. tshark가 있으면 `tshark -r dns.cap -q -z conv,udp` 대화 수와 같아야 함.
- 기능: 7번(대화 요약 탭).

### 4단계: 웹 화면 기본 (Streamlit)
- 목표: 파일을 올리고 탭에서 표로 본다.
- 입력: 1~3단계 레코드.
- 실제 API: `read_text_log(path, log_type)` (`log_type`은 `sshd` 또는 `access`), `read_evtx(path)`, `read_pcap(path)`은 `ParseResult(records, unparsed, notices)`를 반환합니다. `Record(line_number, kind, fields, raw)`가 공통 레코드입니다. `build_conversations(records)`는 `Conversation(uid, protocol, service, stream, a, b, start, duration, packets, bytes, state, history, packet_numbers)` 목록을 만듭니다. `read_pcap`과 `build_conversations`는 `elpa/__init__.py`에서 내보냅니다.
- 출력: 로그 탭, 패킷 탭, 대화 요약 탭. 대화 선택 행은 `st.dataframe(on_select='rerun', selection_mode='single-row')`로 고르고, 해당 uid의 패킷을 강조합니다. 열·필드마다 "?" 도움말은 `help.yaml`을 씁니다.
- 업로드 파일은 `tempfile.NamedTemporaryFile(delete=False, suffix=원래_확장자)`에 쓰고 그 경로를 reader에 전달합니다. `finally`에서 임시 파일을 지우며, 다른 곳에 보관하거나 보내지 않습니다.
- `.streamlit/config.toml`: `server.maxUploadSize = 10` (MB), `server.address = "127.0.0.1"`, `browser.gatherUsageStats = false`.
- `help.yaml`에는 상태 코드(`S0`, `SF`, `REJ`, `RSTO`, `RSTR`, `OTH`)와 열 이름의 한국어 한 줄 설명을 둡니다. 파일이나 설명이 없으면 코드만 `설명 없음`과 함께 표시합니다. `hints.yaml`은 7단계, `filters.yaml`은 6단계에서 만듭니다.
- 완료 확인 방법: OpenSSH_2k.log와 dns.cap을 올리면 세 탭에 각각 2,000줄, 38줄, 8개 대화가 보입니다. "?"를 누르면 `help.yaml` 문구가 나옵니다.
- 기능: 1번(도움 가이드), 3번, 7번.

### 5~11단계 공통: 먼저 알아 둘 말과 원칙
- 함수(function): 입력을 받아 결과를 돌려주는 코드 묶음. 아래 "함수 이름"은 설계 이름이며 아직 코드에 없습니다.
- 데이터클래스(dataclass): 필드 이름이 정해진 작은 데이터 상자. 이미 있는 `Record`, `ParseResult`, `Conversation`이 이 방식입니다(`frozen=True`, 만든 뒤 못 바꿈).
- 세션 상태(`st.session_state`): Streamlit이 화면을 다시 그려도 값을 기억하는 사전(dict).
- 순수 함수: 화면(Streamlit) 없이 입력만으로 결과가 정해지는 함수. 테스트하기 쉬워서 계산은 모두 `elpa/` 안의 순수 함수로 두고, `app.py`는 보여 주기만 합니다.
- 지금 있는 실제 API(이 문서가 기준으로 삼는 것):
  - `ParseResult(records, unparsed, notices, unparsed_lines, unparsed_lines_truncated)` (`elpa/models.py`). `unparsed_lines`는 최대 `MAX_UNPARSED_LINES = 1000`개까지 저장.
  - `Record(line_number, kind, fields, raw)`. `fields` 값은 모두 문자열 또는 `None`.
    - sshd: `kind`는 `decoders.yaml`의 `name`, `fields`는 `invalid`/`user`/`srcip`/`srcport` 또는 `message`. 시간 필드가 없고 시간은 `raw` 앞부분(`Dec 10 06:55:48`)에만 있음. **연도가 없음**.
    - access: `srcip`, `time`(예: `10/Oct/2000:13:55:36 -0700` 형태), `method`, `path`, `status`, `bytes`.
    - evtx: `time`(`TimeCreated`의 `SystemTime`), EventID, `IpAddress`, `TargetUserName`.
    - pcap: `time`(UTC 초 문자열, 예: `"1112172466.496046"`), `src`, `dst`, `sport`, `dport`, `transport`, `protocol`, `flags`, `length`, `summary`. `line_number`가 Wireshark `frame.number`.
  - `Conversation(uid, protocol, service, stream, a, b, start, duration, packets, bytes, state, history, packet_numbers)`. `a`/`b`는 `"IP:포트"`, `start`는 `...Z` 형태 UTC 문자열.
- 새 숫자는 직접 세어 확인한 것만 적습니다. 세지 않은 값은 `확인 못 함`.
- 테스트는 [samples.md](samples.md)의 공개 샘플(`OpenSSH_2k.log`, `apache_logs`, `security.evtx`, `dns.cap`)과, 테스트 안에서 만든 작은 사본(예: 앞부분만 자른 파일)만 씁니다.

### 5단계: 시간 연결 보기
- 목표: 한 탭에서 고른 레코드의 시각 앞뒤 N초를 다른 탭에서 강조.
- 새 파일(설계): `elpa/timeline.py`.
- 데이터 형식:
  - `TimePoint(source, number, when)`: `source`는 `"log"` / `"packet"`, `number`는 `Record.line_number`, `when`은 시간대 정보가 붙은(tz-aware) `datetime` 또는 `None`(시간을 못 읽음).
  - `TimeSettings(log_tz, sshd_year, window_seconds)`: `log_tz`는 시간대 정보가 없는 로그에 붙일 시간대(기본 `Asia/Seoul`), `sshd_year`는 연도가 없는 sshd 줄에 붙일 연도(기본: 사용자가 고르기, 값이 없으면 시간 연결을 끔), `window_seconds`는 앞뒤 몇 초(기본 5, 설계 값).
- 5-1. 시간 읽기: `record_time(record, kind_group, settings) -> datetime | None`
  - pcap: `datetime.fromtimestamp(float(time), timezone.utc)`.
  - access: `%d/%b/%Y:%H:%M:%S %z`로 읽음(시간대가 줄 안에 있음).
  - evtx: ISO 8601로 읽음. 끝이 `Z`면 UTC.
  - sshd: `raw` 앞 `월 일 시:분:초` + `sshd_year` + `log_tz`. 연도는 파일에 없으므로 화면에 "연도는 직접 고른 값"이라고 적음.
  - 못 읽으면 `None`(오류를 내지 않음). 지금 `app.py`의 `_log_time`과 같은 규칙이므로 구현 때 이 함수로 옮겨 한곳에서만 처리.
- 5-2. 목록 만들기: `build_timeline(records, kind_group, settings) -> list[TimePoint]`. 순서는 원래 `line_number` 순서 유지.
- 5-3. 범위 찾기: `numbers_near(points, center: datetime, window_seconds) -> set[int]`. `center - N초 <= when <= center + N초`인 `number`를 돌려줌. `when`이 `None`이면 뺌.
- 5-4. 화면: 로그 표·패킷 표의 행 선택(`on_select='rerun'`)으로 고른 행의 시각을 `st.session_state["time_center"]`에 저장 → 다른 표에서 `numbers_near` 결과 행에 "강조" 글자 열을 붙임(4단계 대화 강조와 같은 방식). [ui.md](ui.md) 결정 1대로 탭은 바꾸지 않고 "패킷 탭에서 강조해 두었습니다" 문구를 띄움.
- 5-5. 시간대 설정: 사이드바에 `log_tz`, `sshd_year`, `window_seconds` 입력. 바꾸면 강조만 다시 계산.
- 입력: 1~2단계 `ParseResult.records`, `TimeSettings`. 출력: 강조할 번호 집합(`set[int]`).
- 완료 확인 방법(테스트 체크):
  - dns.cap 1번 패킷 → `when`이 UTC 1112172466.496046초와 같음(2단계에서 확인한 값).
  - OpenSSH_2k.log 1번 줄: `log_tz`를 UTC와 +9로 바꿨을 때 같은 순간의 UTC 값 차이가 정확히 9시간.
  - 고른 줄의 앞뒤 범위 결과가, 같은 시각 문자열을 `grep`으로 센 줄 번호를 포함함(구체 건수는 확인 못 함, 테스트에서 직접 셈).
  - 시간 없는 레코드(`when=None`)는 강조 대상에서 빠지고 오류가 나지 않음.
- 확인 못 함: 공개 샘플 중 로그와 pcap이 같은 시간대·같은 사건인 쌍. 그래서 "로그 줄 ↔ 패킷" 실제 겹침은 테스트하지 않고, 같은 파일 안의 범위 계산만 확인합니다.
- 기능: 3번.

### 6단계: 필터와 Wireshark 명령 번역
- 목표: 클릭 필터(IP, 포트, 프로토콜, 상태 코드, 시간)로 표를 거르고, 같은 뜻의 Wireshark 디스플레이 필터와 tshark 명령을 옆에 보여 줌.
- 새 파일(설계): `elpa/filters.py`, `filters.yaml`.
- 데이터 형식:
  - `FilterCond(field, op, value)`: `field`는 우리 필드 이름(`src`, `dst`, `port`, `protocol`, `srcip`, `status` 등), `op`는 `"=="`만(처음에는 같음만 지원, 범위·정규식은 나중), `value`는 문자열. `port`는 `sport` 또는 `dport` 중 하나가 같으면 맞음(Wireshark `udp.port`와 같은 뜻).
  - 여러 조건은 모두 맞아야 함(AND). OR는 이번 단계에서 하지 않음.
- `filters.yaml` 모양(설계 예시, 키는 우리 필드):
  | 우리 필드 | 대상 | Wireshark | tshark `-e` | zeek-cut | awk(access.log) |
  |---|---|---|---|---|---|
  | `src` | pcap | `ip.src == {v}` | `ip.src` | `id.orig_h` | - |
  | `dst` | pcap | `ip.dst == {v}` | `ip.dst` | `id.resp_h` | - |
  | `port` | pcap | `udp.port == {v} \|\| tcp.port == {v}` | - | - | - |
  | `protocol` | pcap | 이름을 소문자로(`dns`) | - | `service` | - |
  | `srcip` | access | - | - | - | `$1` |
  | `status` | access | - | - | - | `$9` |
  - `{v}`에는 사용자가 고른 값이 들어감. 값은 화면에 있던 값 중에서만 고르게 해서(자유 입력 없음) 이상한 글자가 명령에 들어가지 않게 함. 명령 문자열은 **보여 주기만 하고 실행하지 않음**.
  - IPv6 주소면 `ip.src` 대신 `ipv6.src`를 씀(`:` 포함 여부로 판단).
  - 번역이 없는 필드는 "번역 없음"으로 표시.
- 6-1. `load_filters(path) -> dict`: `yaml.safe_load`로 읽음. 파일이 없거나 형식이 틀리면 빈 표 + 안내(앱은 계속 동작).
- 6-2. `apply_filters(records, conds) -> list[Record]`: 순수 함수, 원래 순서 유지.
- 6-3. `to_wireshark(conds, table) -> str | None`, `to_tshark(conds, table, filename) -> str`: 예) `tshark -r dns.cap -Y "udp.port == 53 || tcp.port == 53"`. 파일 이름은 따옴표로 감쌈.
- 6-4. `to_awk(conds, table, filename) -> str | None`: access.log만. 예) `awk '$9 == "404"' apache_logs`.
- 6-5. 화면: 표 위에 필터 칩(고른 조건 목록, 하나씩 지우기), 아래에 명령 상자(`st.code`). 결과 0건이면 [ui.md](ui.md) 5.4 문구.
- 입력: 레코드, `list[FilterCond]`, `filters.yaml`. 출력: 걸러진 `list[Record]`와 명령 문자열.
- 완료 확인 방법(테스트 체크):
  - dns.cap에서 `port == 53` → 38개(2단계에서 "UDP 53번 포트 38개"로 확인한 값). tshark 결과와의 비교는 tshark 설치 후(지금 Mac mini에 tshark 없음, 확인 못 함).
  - apache_logs에서 `status == 404` → 213줄(1단계 값), 만든 awk 명령을 실제로 돌린 줄 수와 같음.
  - 만든 Wireshark 문자열이 기대 문자열과 글자 하나까지 같음(문자열 비교 테스트).
  - `filters.yaml`이 없을 때 앱이 멈추지 않음.
- 기능: 2번(가장 중요).

### 7단계: 규칙 기반 경고 카드와 오해 힌트
- 목표: `rules.yaml` 규칙으로 경고 카드를, `hints.yaml`로 오해 힌트를 만든다. AI 사용 안 함. [ui.md](ui.md) 3.2~3.5의 경고 카드는 4단계에서 미루었고 이 단계에서 만듭니다.
- 새 파일(설계): `elpa/rules.py`, `elpa/hints.py`, `rules.yaml`, `hints.yaml`.
- `rules.yaml` 칸:
  | 칸 | 뜻 | 참고 |
  |---|---|---|
  | `id`, `version` | 고유 번호, 고친 횟수 | Suricata sid/rev |
  | `대상` | 적용할 로그 종류(`sshd`, `access`, `evtx`, `pcap`) | Sigma logsource |
  | `조건` | "이 필드가 이 값" 목록. 모두 맞아야 함(6단계 `FilterCond` 재사용) | Sigma selection |
  | `count`, `seconds`, `track`, `unique` | 몇 초 안에 몇 번, 누구 기준으로(`track`: 예 `srcip`), 서로 다른 값 세기(`unique`: 예 `dport`) | Suricata threshold, Wazuh frequency/timeframe/same_srcip |
  | `중복 억제` | 같은 경고를 몇 초 동안 다시 안 냄 | Zeek Notice identifier, Wazuh ignore |
  | `level` | 높음/중간/낮음 | Sigma level, Wazuh level |
  | `category` | 쉬운 한국어 분류(예: 정찰 시도) | Suricata classtype |
  | `msg`, `왜 이상한가`, `다음 단계`, `wireshark_filter` | 카드 문구 | Zeek Notice |
  | `오해 주의` | 경고가 나도 문제가 아닐 수 있는 경우 | Sigma falsepositives |
  | `suricata_example` | 참고용 룰 텍스트, 실행 안 함 | Suricata |
- 데이터 형식:
  - `Rule`: 위 칸을 그대로 담은 데이터클래스(`frozen=True`).
  - `Alert(rule_id, track_value, level, category, msg, evidence, confidence, confidence_reason)`: `evidence`는 근거 번호 튜플(`tuple[int, ...]`, 로그는 `line_number`, 패킷은 `frame.number`), `confidence`는 `"근거 충분"` / `"더 확인 필요"`.
  - `Hint(hint_id, target, text, evidence)`: 경고가 아닌 설명.
- 7-1. `load_rules(path) -> list[Rule]`: 모르는 칸이나 빠진 필수 칸이 있으면 그 규칙만 건너뛰고 안내(`notices`처럼 문자열 목록).
- 7-2. 조건 맞추기: 6단계 `apply_filters` 재사용.
- 7-3. 시간 창 세기: `track` 값별로 시간순 정렬 → 앞뒤 두 개 포인터(슬라이딩 윈도: 일정 길이의 시간 칸을 밀면서 세는 방법)로 `seconds` 안에 `count`개 이상이면 경고. 시간은 5단계 `record_time` 재사용. 시간이 `None`이면 그 레코드는 세지 않고 `더 확인 필요` 이유에 적음.
- 7-4. 중복 억제: 같은 `(rule_id, track_value)`는 창이 겹치면 카드 하나로 합치고 근거 줄을 모두 모음(Wazuh `previous_output`처럼).
- 7-5. 신뢰도: 근거를 하나씩 다시 확인해 맞는 것만 인정한다는 생각을 따릅니다(cloudflare/security-audit-skill의 "independently verified findings" 방식, https://github.com/cloudflare/security-audit-skill).
  - `근거 충분`: 조건이 모두 맞고, 근거가 `count` 이상이고, 근거 번호로 원본(`Record.raw`)을 다시 찾았을 때 같은 조건이 다시 맞음.
  - `더 확인 필요`: 일부 필드가 비었거나, `ParseResult.unparsed > 0`, 근거 수가 `count`와 딱 같거나, 시간 못 읽은 레코드가 있음. 이유를 한 줄로 붙임.
- 7-6. 힌트: `hints.yaml`은 `id`, `대상`, `조건`, `text`(쉬운 설명)만 가짐. "특이하지만 공격 아님"(재전송, RST, DNS 실패 등)과 3단계 `state` 코드 설명이 여기 들어감. 예: `state == S0`인 UDP 대화 → "응답이 안 보였을 뿐, 캡처 위치 때문일 수 있음".
- 7-7. 화면: [ui.md](ui.md) 3.5 모양. 각 탭 위 `st.expander`. 근거 번호를 누르면(행 선택) 그 줄/패킷을 강조. `suricata_example`은 `st.code`로 보여 주기만 함.
- 범위: 규칙은 공부용 탐지 예시만 둡니다. 탐지를 피하는 방법이나 공격 방법은 넣지 않습니다.
- 입력: 레코드, `ParseResult.unparsed`, `rules.yaml`, `hints.yaml`. 출력: `list[Alert]`, `list[Hint]`.
- 완료 확인 방법(테스트 체크):
  - OpenSSH_2k.log에 "같은 `srcip`의 sshd 실패(`kind`가 sshd 실패)가 60초 안에 5번 이상" 규칙: 설계 때 적은 값은 출발지 IP 9개, 가장 많은 것 183.62.140.253입니다. 183.62.140.253의 `Failed password for` 줄은 `grep`으로 286줄 확인(2026-10-30). 60초 창 규칙을 건 결과(IP 9개 포함)는 아직 코드로 확인 못 함이라 구현 때 다시 세어 기대값으로 씁니다.
  - 카드의 근거 번호가 `grep -n` 결과 줄 번호와 같음.
  - 카드에 `level`, `오해 주의`, 신뢰도가 보임.
  - dns.cap 대화에 힌트 규칙을 걸었을 때 나오는 힌트 수는 확인 못 함(대화별 `state` 값을 아직 확인 안 함).
  - `rules.yaml`에 틀린 규칙 하나를 넣으면 그 규칙만 빠지고 나머지는 동작.
- 구현 결과 맞춤(PR #21, main 코드에서 확인 2026-11-01):
  - 근거 강조: 표 행을 눌러 고르는 방식이 아니라, 카드마다 있는 선택 상자(`st.selectbox` "[원본 보기] 근거 줄/패킷 강조")에서 근거 번호를 고르면 그 줄/패킷을 강조합니다.
  - `rules.yaml`의 `왜 이상한가` 칸은 영어 별칭 `why`도 받습니다(`왜 이상한가`가 있으면 그것을 씀).
  - `더 확인 필요` 판단의 근거 수 비교는 `근거 수 <= count`입니다(설계 문구 "딱 같음"보다 넓음, 화면 이유 문구는 "기준과 딱 같습니다"로 남아 있음).
  - **sshd는 연도가 없어서 사이드바 "sshd 연도"를 넣기 전까지 시간을 읽지 못해 sshd 경고가 0건입니다.** 화면에 이 안내를 보이게 해야 합니다(지금은 사이드바에 "연도는 직접 고른 값" 문구만 있음). 함수를 설정 없이 직접 부르면 기본 연도 2023을 씁니다(`elpa/rules.py`, 테스트용).
- 기능: 4번(경고 카드), 5번(오해 힌트).

### 7.5단계: 계층 도움 상자 (사용자 요청 기능)
- 목표: 패킷 한 줄이나 로그 한 줄을 고르면, 그 사건이 어느 **계층**에 속하는지 그림으로 보여 주고, "이런 일이 언제, 왜 생기는지" 예시 상황을 쉬운 한국어로 보여 준다.
- 말 풀이(처음 한 번만):
  - 계층(layer): 네트워크 통신을 맡은 일별로 나눈 층. 이 도구는 4층만 씁니다. 링크(같은 망 안 전달, 예: 이더넷) → IP(주소로 길 찾기) → 전송(포트·연결 관리, 예: TCP/UDP) → 응용(실제 서비스 내용, 예: DNS).
  - 로그 종류: 로그는 패킷 계층 대신 "어떤 기록인지"로 나눕니다. 예: 인증 로그(로그인 기록, sshd·evtx), 웹 접속 로그(access.log).
  - 시나리오(scenario): "이런 기록이 보이는 흔한 상황"을 적은 짧은 설명. 방어·공부용 설명만 넣습니다.
- **왜 7단계에 넣지 않고 따로 두나**
  - 7단계는 여러 줄을 세어(`count`, `seconds`) 조건이 맞을 때만 나오는 경고 카드입니다. 계층 도움 상자는 줄 하나만 보고 **항상** 나오는 설명이라, 세는 규칙·신뢰도가 필요 없습니다.
  - 7단계에 섞으면 `rules.yaml`/`hints.yaml`에 성격이 다른 칸이 늘어나 초보자가 읽기 어렵습니다.
  - 그래도 7단계 다음에 두어 7단계의 YAML 읽기 방식(잘못된 항목만 건너뛰고 안내)과 `hints.yaml` 힌트를 같이 보여 줄 수 있게 합니다.
  - 번호는 기존 8~11단계를 바꾸지 않으려고 `7.5단계`로 둡니다(이미 다른 문서·PR이 8~11 번호를 씀).
- 새 파일(설계): `elpa/layer_help.py`, `layers.yaml`, `scenarios.yaml`.
- 데이터 형식:
  - `LayerInfo(id, name, order, text)`: `id`는 `link`/`ip`/`transport`/`app`/`log_auth`/`log_web`, `order`는 그림에서 아래→위 순서(1~4, 로그는 0).
  - `Scenario(id, layer, match, title, why, check_next, caution)`: `match`는 조건 사전(아래 매핑 규칙), `check_next`는 "다음에 볼 것" 목록.
  - `LayerHelp(layers: tuple[LayerInfo, ...], current: str | None, scenarios: tuple[Scenario, ...], notes: tuple[str, ...])`: 화면이 그대로 그리는 결과. `current`가 `None`이면 "설명 없음".
- `layers.yaml` 모양(예시 3개):
  ```yaml
  - id: transport
    name: 전송 계층
    order: 3
    text: 포트 번호로 어떤 프로그램끼리 이야기하는지 정하고, TCP는 연결을 관리합니다.
  - id: app
    name: 응용 계층
    order: 4
    text: DNS, HTTP처럼 사람이 쓰는 서비스의 실제 내용입니다.
  - id: log_auth
    name: 인증 로그
    order: 0
    text: 누가 언제 로그인을 시도했고 성공했는지 남기는 기록입니다.
  ```
- `scenarios.yaml` 모양(예시 3개):
  ```yaml
  - id: dns_query_answer
    layer: app
    match: {source: packet, kind: DNS}
    title: 이름을 IP 주소로 바꾸는 질문과 대답
    why: 웹 주소를 열 때 컴퓨터가 먼저 DNS 서버에 주소를 묻습니다.
    check_next: [같은 대화(udp.stream)에 대답이 있는지, 대화 요약의 상태 값]
    caution: DNS가 많이 보이는 것 자체는 보통 정상입니다.
  - id: udp_one_side_only
    layer: transport
    match: {source: conversation, protocol: UDP, state: S0}
    title: 한쪽 방향만 보이는 UDP 대화
    why: 대답이 없었거나, 캡처한 위치에서 대답이 지나가지 않았을 수 있습니다.
    check_next: [반대 방향 패킷이 있는지, 캡처한 위치]
    caution: 응답이 안 보였다고 바로 문제라고 단정하지 않습니다.
  - id: ssh_login_failed
    layer: log_auth
    match: {source: log, kind: sshd 실패}
    title: SSH 로그인 실패 기록
    why: 비밀번호를 틀렸거나 없는 계정 이름으로 접속을 시도하면 남습니다.
    check_next: [같은 srcip의 성공 기록이 있는지, 7단계 경고 카드]
    caution: 한두 번 실패는 오타일 때가 많습니다.
  ```
  - 두 파일 모두 `yaml.safe_load`로만 읽습니다. 빠진 칸이 있는 항목은 건너뛰고 `notes`에 안내합니다. 파일이 없으면 상자에 "설명 없음"만 보이고 앱은 계속 동작합니다.
  - 시나리오 문구는 "왜 보이는지 + 무엇을 확인할지"만 씁니다. 공격 방법이나 탐지 피하는 방법은 넣지 않습니다(리뷰 때 확인).
- 매핑 규칙(코드 값 → 계층). 실제 값은 지금 코드 기준:
  | 입력 | 값 | 계층 `current` |
  |---|---|---|
  | 패킷 `Record.kind` | `DNS` 등 응용 이름 | `app` |
  | 패킷 `Record.kind` | `TCP`, `UDP` | `transport` |
  | 패킷 `Record.kind` | `IP`, `IPv6` | `ip` |
  | 패킷 `Record.kind` | `Ethernet` | `link` |
  | 패킷 `Record.kind` | `Raw` 또는 표에 없는 값 | `None` → "설명 없음" |
  | 로그 `Record.kind` | `sshd 실패`, `sshd 성공`, `sshd 없는 사용자`, `sshd`, `evtx` | `log_auth` |
  | 로그 `Record.kind` | `access.log` | `log_web` |
  | 대화 `Conversation.protocol` | `TCP`/`UDP` | `transport` (그리고 `service`가 응용 이름이면 응용 계층도 함께 표시) |
  - 패킷 `kind`는 `summary`(예: `Ethernet / IP / UDP / DNS`)의 맨 끝 이름과 같습니다. 그래서 그림에는 `summary`에 나온 층을 모두 "들어 있음"으로, `current`만 "지금 고른 것"으로 표시합니다.
  - 응용 이름 목록(`DNS` 등)은 `layers.yaml`에 `app_names`로 두어 코드에 박지 않습니다.
  - 시나리오는 `match`의 모든 키가 같을 때만 고릅니다(같음 비교만). 여러 개가 맞으면 파일 순서대로 최대 3개. 하나도 없으면 "이 기록에 맞는 예시 상황: 설명 없음".
  - 대화 `state` 설명은 7단계 `hints.yaml`과 겹치지 않게, 상태 코드 뜻은 `help.yaml`/`hints.yaml`, "상황 예시"만 `scenarios.yaml`에 둡니다.
- 하위 단계:
  - 7.5-1. `load_layers(path)`, `load_scenarios(path)`: 읽기 + 칸 검사. 출력: 튜플과 안내 목록.
  - 7.5-2. `layer_of(record_or_conversation, source) -> str | None`: 위 표 그대로. 순수 함수.
  - 7.5-3. `scenarios_for(item, source, scenarios) -> tuple[Scenario, ...]`.
  - 7.5-4. `build_layer_help(item, source, layers, scenarios) -> LayerHelp`.
  - 7.5-5. 화면: 4단계 행 선택(`on_select='rerun'`)으로 고른 행이 하나일 때 표 아래 `st.container(border=True)` 상자에 표시(팝업 대신. 이유는 [ui.md](ui.md) 3.6). 그림은 아래 7.5-6.
  - 7.5-6. 계층 그림: 층마다 한 줄씩 위→아래로 쌓은 칸. 지금 층은 굵은 테두리 + `▶` 기호 + "지금 고른 것" 글자(색만으로 구분 안 함). Streamlit 기본 요소(`st.columns`, `st.markdown`)로 만들고 외부 JavaScript·외부 컴포넌트는 쓰지 않습니다. HTML을 써야 하면 `st.markdown(..., unsafe_allow_html=True)`로 우리가 만든 고정 틀만 쓰고, 그 안에 들어가는 **모든 값(원본 값과 YAML 문구 둘 다)은 `html.escape`를 거친 뒤** 넣습니다.
- 입력: 고른 `Record` 하나 또는 `Conversation` 하나, `layers.yaml`, `scenarios.yaml`. 출력: `LayerHelp`.
- 완료 확인 방법(테스트 체크, 공개 샘플만):
  - dns.cap 1번 패킷: `kind == "DNS"`, `summary == "Ethernet / IP / UDP / DNS"` → `current == "app"`, 그림에 4층 모두 "들어 있음". (dns.cap 38개 모두 `kind=DNS`, 같은 요약임을 2026-10-31 Mac mini에서 확인)
  - dns.cap 대화 8개: 모두 `protocol=UDP`, `state=SF`, `history=Dd`(2026-10-31 확인) → `current == "transport"`, `udp_one_side_only`(S0) 시나리오는 나오지 않음.
  - OpenSSH_2k.log의 `Failed password for` 줄 하나 → `log_auth`, `ssh_login_failed` 시나리오.
  - apache_logs 한 줄 → `log_web`. security.evtx 한 건 → `log_auth`.
  - `kind="Raw"`로 만든 작은 테스트 레코드 → "설명 없음", 오류 없음.
  - `<script>`가 든 값을 넣은 테스트 레코드 → 화면용 문자열에 `&lt;script&gt;`로 바뀌어 들어감.
  - `layers.yaml`이 없을 때 앱이 멈추지 않음.
- 확인 못 함: TCP·IPv6·ARP처럼 dns.cap에 없는 계층의 실제 표시(공개 샘플에 아직 없음). `st.container(border=True)`가 Streamlit 1.66.1에서 그대로 동작하는지는 구현 때 확인. evtx를 EventID별로 더 나눌지(예: 4624 성공)는 정하지 않음.
- 구현 결과 맞춤(PR #23, main 코드에서 확인 2026-11-01):
  - `layers.yaml` 실제 모양은 최상위 `{app_names: [...], layers: [...]}`입니다. 읽기 함수는 위 설계의 목록 모양(항목 안 `app_names` 포함)도 받습니다.
  - 그림에서 이 기록에 없는 층은 `없음`으로 표시합니다([ui.md](ui.md) 3.6).
  - 대화 시나리오는 `match`의 `kind` 자리에 `Conversation.service`(예: `DNS`)를 넣어 비교합니다.
  - `layer_of`와 읽기 함수에는 응용 이름 목록 등 선택 인자가 더 있습니다(없으면 `layers.yaml` 값 사용).
  - `scenarios.yaml`에는 8개가 있습니다: `dns_query_answer`, `udp_one_side_only`, `udp_dns_conversation`, `ssh_login_failed`, `ssh_login_accepted`, `ssh_invalid_user`, `web_access_request`, `windows_event_auth`.
  - 로그 탭에서 도움 상자는 필터 명령 번역 상자 아래에 나옵니다.
  - 후속 작업: 문구에 남은 영어 용어 `EventID`, `udp.stream`, `srcip`를 쉬운 말로 바꾸거나 처음 나올 때 뜻을 붙입니다.
- 기능: 1번(도움 가이드), 5번(오해 힌트)과 연결.

### 8단계: 열 고르기와 내보내기
- 목표: 보고 싶은 열만 골라 보고 CSV로 내보낸다. 4단계에서 미룬 기능입니다.
- 새 파일(설계): `elpa/export.py`.
- 데이터 형식: `ColumnChoice(tab, columns: tuple[str, ...])`. 열 이름은 4단계 표 머리글과 같게 둠. 고른 값은 `st.session_state["columns_<탭>"]`에 저장.
- 8-1. `table_rows(records, columns, settings) -> list[dict[str, str]]`: 4단계 `build_log_table`/`build_packet_table`/`build_conversation_table` 결과에서 고른 열만 남김. 시간 표시는 5단계 설정 재사용.
- 8-2. `to_csv(rows, columns) -> bytes`: 표준 `csv` 모듈, UTF-8 BOM(엑셀이 한글을 바르게 여는 표시) 붙임. 줄 순서는 화면과 같음(6단계 필터 반영).
  - 수식 주입 방지: 칸 값이 `=`, `+`, `-`, `@`로 시작하면 앞에 `'`를 붙임(엑셀이 값을 수식으로 실행하지 않게 하는 일반 방어).
- 8-3. 같은 일을 하는 명령: `filters.yaml` 번역 재사용.
  - 패킷: `tshark -r 파일 -T fields -E separator=, -e ip.src -e ...`
  - Zeek 로그: `zeek-cut id.orig_h ...`
  - access.log: `awk '{print $1","$9}' 파일`
  - 번역 없는 열이 있으면 그 열은 명령에서 빼고 "번역 없음"으로 표시.
- 8-4. 화면: `st.multiselect`로 열 고르기, `st.download_button`으로 CSV 받기(파일은 서버에 저장하지 않음).
- 입력: 탭의 레코드, 고른 열, 시간대 설정. 출력: CSV 바이트와 명령 문자열.
- 완료 확인 방법(테스트 체크):
  - apache_logs에서 출발지 IP·상태 코드만 골라 만든 CSV(머리글 제외)가 `awk '{print $1","$9}' apache_logs` 결과와 줄마다 같음. 줄 수 10,000(1단계 값). 1단계 정규식에 안 맞는 줄이 있으면 차이가 날 수 있으니 차이는 테스트에서 직접 확인.
  - dns.cap 패킷 CSV 줄 수 38. tshark 결과와 비교는 tshark 설치 후(확인 못 함).
  - `=`로 시작하는 값을 넣은 작은 테스트 데이터에서 `'`가 붙음.
- 구현 결과 맞춤(PR #25, main 코드에서 확인 2026-11-01):
  - 명령 번역은 access.log → `awk`, 패킷 → `tshark`만 보여 줍니다. 대화·sshd·evtx 표는 `번역 없음`입니다. `zeek-cut`은 10단계(Zeek conn.log 읽기) 뒤에만 보여 줍니다.
  - tshark 결과와 CSV 비교는 하지 않았습니다(Mac mini에 tshark 없음, 확인 못 함).
  - **어긋난 점(고칠 것)**: CSV에는 6단계 필터가 반영되지만, 화면의 명령 문자열(`to_export_command`)에는 6단계 필터 조건이 들어가지 않습니다. 그래서 필터를 건 상태에서는 명령 결과와 CSV가 다를 수 있습니다.
- 기능: 8번.

### 8.5단계: 시나리오 학습 화면 (사용자 요청 기능)
- 순서: 8단계 다음, 9~11단계보다 먼저 만듭니다. 9단계(공부 노트)가 나중에 "본 시나리오"를 노트에 넣을 수 있게 하기 위해서입니다. 기존 8~11 번호는 바꾸지 않으려고 `8.5`로 둡니다.
- 목표: 첫 화면에서 시나리오 카드 여러 장을 좌우로 넘겨 고르고, 고른 시나리오를 "원인 → 그 결과 생기는 패킷/로그 → 결과" 카드 3장으로 한 장씩 넘겨 본다. 공부 전용이며 **올린 파일과 연결하지 않습니다**.
- 말 풀이(처음 한 번만):
  - 스와이프(swipe): 마우스나 손가락으로 화면을 좌우로 끌어 넘기는 동작.
  - 컴포넌트(component): Streamlit에 없는 화면 요소를 HTML/JavaScript로 직접 만들어 끼우는 것.
  - 양방향 컴포넌트: Python → 화면으로 값을 보내고, 화면 → Python으로 값(여기서는 고른 카드 번호)을 돌려받는 컴포넌트.
  - CDN: 인터넷의 다른 서버에서 JavaScript 파일을 받아 쓰는 방식. 여기서는 쓰지 않습니다.
- 화면 구조: 첫 화면 위쪽에 탭 `시나리오 학습` / `분석`을 둡니다. 지금 있는 분석 기능(업로드, 로그·패킷·대화 탭, 경고 카드 등)은 동작을 바꾸지 않고 `분석` 탭 안으로 옮깁니다. ([ui.md](ui.md) 3.7)
- 새 파일(설계): `learning.yaml`, `elpa/learning.py`, `elpa/components/card_swiper/index.html`(로컬 정적 파일, 외부 파일 불러오기 없음).
- 고른 시나리오(공개 샘플 기준, 숫자는 직접 확인한 값만):
  | id | 제목 | 근거 샘플 | 확인한 값 |
  |---|---|---|---|
  | `ssh_repeated_fail` | 같은 곳에서 SSH 로그인 실패가 반복됨 | OpenSSH_2k.log | `Failed password for` 520줄, 그중 183.62.140.253이 286줄(grep, 2026-10-30) |
  | `dns_query_answer` | DNS 질문과 대답 | dns.cap | 패킷 38개 모두 DNS, 대화 8개 모두 UDP·`SF`·`Dd`(2026-10-31) |
  | `web_404` | 없는 웹 주소 요청(404)이 보임 | apache_logs | 상태 404가 213줄. 짧은 시간에 몰린 "폭주" 여부는 확인 못 함이라 "몰림" 표현은 쓰지 않음 |
  | `udp_one_side` | 한쪽 방향만 보이는 UDP | 없음 → `교육용 예시` 가짜 데이터 | dns.cap에는 `S0` 대화가 없음(모두 `SF`) |
  - `교육용 예시` 데이터는 문서용 주소(192.0.2.x, 198.51.100.x)만 쓰고 카드에 `교육용 예시` 배지를 항상 붙입니다.
  - 내용은 "무슨 일이 생기면 어떤 기록이 남고, 무엇을 확인하나"만 씁니다. 공격 방법·도구 사용법·탐지 피하는 법은 넣지 않습니다.
- `learning.yaml` 모양(`yaml.safe_load`로만 읽음):
  ```yaml
  scenarios:
    - id: dns_query_answer
      title: DNS 질문과 대답
      sample: dns.cap            # 또는 교육용 예시
      example_only: false
      stages:                    # 정확히 3개: cause, evidence, result
        - kind: cause
          title: 원인
          text: 컴퓨터가 웹 주소의 IP를 몰라 DNS 서버에 묻습니다.
        - kind: evidence
          title: 생기는 패킷
          text: UDP 53번 포트로 질문 1개, 대답 1개가 오갑니다.
          lines: ["Ethernet / IP / UDP / DNS"]
        - kind: result
          title: 결과
          text: 대화 상태는 SF(양쪽 모두 보임)이고, 컴퓨터는 받은 IP로 접속합니다.
    - id: udp_one_side
      title: 한쪽 방향만 보이는 UDP
      sample: 교육용 예시
      example_only: true
      stages:
        - {kind: cause, title: 원인, text: 질문은 보냈지만 대답이 캡처 위치를 지나가지 않았습니다.}
        - {kind: evidence, title: 생기는 패킷, text: "192.0.2.10 → 198.51.100.53 UDP 53 질문만 있음", lines: ["교육용 예시: 192.0.2.10:40000 → 198.51.100.53:53"]}
        - {kind: result, title: 결과, text: 대화 상태 S0. 바로 문제라고 단정하지 말고 캡처 위치를 확인합니다.}
    - id: ssh_repeated_fail
      title: SSH 로그인 실패 반복
      sample: OpenSSH_2k.log
      example_only: false
      stages:
        - {kind: cause, title: 원인, text: 누군가 여러 비밀번호로 로그인을 계속 시도합니다.}
        - {kind: evidence, title: 생기는 로그, text: 같은 출발지 IP의 Failed password 줄이 이어집니다. 이 샘플에서는 183.62.140.253이 286줄입니다.}
        - {kind: result, title: 결과, text: 7단계 경고 카드가 뜰 수 있습니다. 같은 IP의 성공 기록이 있는지 확인합니다.}
  ```
  - 검사: `id`·`title`·`stages`가 없거나, `stages`가 3개가 아니거나, `kind` 순서가 `cause → evidence → result`가 아니면 그 시나리오만 건너뛰고 안내 문구를 남깁니다(7·7.5단계와 같은 방식). 파일이 없거나 형식이 틀리면 "시나리오 없음" 안내만 보이고 `분석` 탭은 그대로 동작합니다.
  - Streamlit 화면(`st.markdown` 등)에 넣는 모든 값(`title`, `text`, `lines`)은 `html.escape`를 거칩니다. 컴포넌트에는 원래 문자열을 넘기고 JavaScript에서 `innerHTML` 대신 `textContent`로만 넣어 HTML로 해석되지 않게 합니다(이미 이스케이프한 값을 `textContent`로 넣으면 `&lt;` 글자가 그대로 보이므로 두 번 하지 않음).
- 데이터 형식: `LearningStage(kind, title, text, lines: tuple[str, ...])`, `LearningScenario(id, title, sample, example_only, stages: tuple[LearningStage, ...])`.
- Streamlit에는 스와이프가 없으므로 카드 넘기기 컴포넌트를 만듭니다.
  - `streamlit.components.v1.declare_component("card_swiper", path=로컬_폴더)`로 선언합니다. 설치된 1.66.1에서 `declare_component(name, path=None, url=None)` 모양을 직접 확인했습니다(2026-11-01). `url`(개발 서버)은 쓰지 않고 `path`만 씁니다.
  - `components.html(...)`은 HTML을 iframe에 보여 주기만 하고 값을 돌려주지 못합니다(한 방향). 1.66.1 함수 모양에서 반환값이 화면 요소(`DeltaGenerator`)인 것을 확인했습니다. 그래서 고른 번호를 받으려면 `declare_component`를 씁니다.
  - 1.66.1에는 `streamlit.components.v2` 모듈도 있지만, 이번 설계에 맞는지는 확인 못 함이라 v1을 기준으로 합니다.
  - 공식 문서 페이지(docs.streamlit.io)는 이번에 열어 보지 않아 문서와의 대조는 확인 못 함. 함수 모양만 설치본에서 확인했습니다.
  - 컴포넌트 입력: `cards`(제목 목록, 화면에서는 `textContent`로 넣음), `index`(지금 번호), `key`. 출력: 사용자가 바꾼 번호(`int`) 또는 `None`(아직 안 바꿈).
  - 모양: 옆 카드가 살짝 보이는 끌기형 캐러셀 + 좌우 화살표 + 진행 막대(리뷰어 참고: lucian-uxui #339, 원문 세부는 확인 못 함). [ui.md](ui.md) 3.8.
  - 화면 안 동작: 마우스/터치로 끈 거리가 일정 이상이면 왼쪽/오른쪽으로 넘김(기준 거리는 구현 때 정함), `←`/`→` 키, `이전`/`다음` 버튼. 바뀌면 `Streamlit.setComponentValue(번호)`로 Python에 돌려줌. 버튼은 `<button>`이라 Tab 키로 닿고 `aria-label`을 붙입니다.
  - 컴포넌트가 실패하거나 JavaScript가 막혀도 쓸 수 있게, 컴포넌트 아래에 Streamlit 기본 `st.button("이전")`/`st.button("다음")`도 둡니다(접근성 대체 수단).
  - 번호 저장: `st.session_state["learning_index"]`(첫 화면), `st.session_state["learning_stage"]`(시나리오 페이지, 0~2), `st.session_state["learning_open"]`(연 시나리오 id 또는 `None`). 매 실행 때 저장값을 컴포넌트의 `index`로 다시 넘겨, 다시 그려도 첫 카드로 돌아가지 않게 합니다. 번호는 `0 <= i < 카드 수`로 잘라 씁니다.
- 하위 단계:
  - 8.5-1. `learning.yaml` 작성(위 4개 시나리오) + `load_learning(path) -> tuple[tuple[LearningScenario, ...], list[str]]`(검사·안내).
  - 8.5-2. `app.py`를 `시나리오 학습` / `분석` 탭으로 나누고 기존 기능을 `분석` 탭으로 옮김(동작 변경 없음, 기존 테스트 그대로 통과).
  - 8.5-3. 카드 넘기기 컴포넌트(로컬 `index.html`, 외부 파일 없음) + Python 래퍼 `card_swiper(cards, index, key) -> int | None`.
  - 8.5-4. 첫 화면: 카드 한 장 크게 + `n / 전체` 표시 + `열기` 버튼. `교육용 예시` 배지.
  - 8.5-5. 시나리오 페이지: 단계 카드 한 장씩(원인 → 생기는 패킷/로그 → 결과), 클릭/탭 또는 `다음`으로 넘김, `처음으로` 버튼.
  - 8.5-6. 세션 상태 저장과 범위 자르기.
  - 8.5-7. 테스트.
- 완료 확인 방법(테스트 체크):
  - 카드가 그려짐: `learning.yaml`의 시나리오 4개 → 첫 화면 카드 수 4(Streamlit `AppTest`로 확인, 컴포넌트 iframe 안쪽은 AppTest로 못 볼 수 있어 대체 버튼과 `n / 4` 글자로 확인).
  - 넘기기: `다음` 버튼 → 번호 0→1, 마지막에서 `다음` → 그대로 3(넘치지 않음). 컴포넌트가 1을 돌려주면 `learning_index == 1`. 실제 마우스 스와이프와 키보드 화살표는 브라우저에서 손으로 확인(자동 테스트 방법은 확인 못 함).
  - 다시 실행해도 유지: 번호 2로 바꾼 뒤 다른 위젯을 눌러 다시 실행 → 여전히 2.
  - 시나리오마다 단계 3개, 순서 `cause → evidence → result`.
  - 이스케이프: `title: "<script>x</script>"`인 테스트 YAML → 화면 문자열에 `&lt;script&gt;`.
  - 잘못된 항목: 단계가 2개인 시나리오 하나를 섞은 YAML → 그 시나리오만 빠지고 안내 1개, 나머지 3개 표시. YAML 문법 오류 파일 → "시나리오 없음", 앱 멈추지 않음.
  - 숫자 문구 확인: `ssh_repeated_fail`의 286줄, `web_404`의 213줄이 grep 결과와 같음.
  - 외부 주소 없음: `index.html`에 `http://`/`https://`로 불러오는 `<script src>`나 `<link>`가 없음.
- UI 리뷰 반영(2026-11-01, 화면 캡처와 main 코드로 확인). 아래 하위 단계를 8.5단계에 더합니다.
  - 8.5-8. 파일 없이도 첫 화면: 지금 `app.py`는 두 업로더가 모두 비면 `st.info("아직 파일이 없습니다")` 뒤 `st.stop()`을 불러 탭이 아예 안 그려집니다. 고칠 설계: `st.stop()`을 없애고, 파일이 없어도 `시나리오 학습` 카드 홈을 그립니다. `분석` 탭 안의 각 탭은 자기 파일이 없을 때만 그 탭 전용 빈 상태 문구를 보여 줍니다(예: 로그 탭 "로그 파일을 올리면 여기에 표가 나옵니다").
  - 8.5-9. 업로드 칸 줄이기: 지금 업로드 두 칸과 `로그 형식` 선택이 항상 펼쳐져 화면을 약 450px 밀어냅니다(리뷰 측정값). 업로드 칸은 사이드바로 옮깁니다(이미 사이드바에 시간 설정이 있어 한곳에 모임). 사이드바가 너무 길어지면 `st.expander("파일 올리기")`로 접는 방식을 대안으로 둡니다. 파일이 올라가 있으면 펼친 상태로 시작하지 않습니다.
  - 8.5-10. 테마 색: 지금 `.streamlit/config.toml`에 `[theme]`이 없어 기본 빨강 강조색(리뷰 기록 `#ff4b4b`)이 열 고르기 칩에 쓰여 오류처럼 보입니다. `[theme]`에 `base = "dark"`, `primaryColor = "#38BDF8"`(하늘색), `backgroundColor = "#0E1117"`, `secondaryBackgroundColor = "#262730"`, `textColor = "#FAFAFA"`를 둡니다. 대비(직접 계산, WCAG 공식): `#38BDF8` 대 배경 `#0E1117` 8.82:1, 대 `#262730` 6.93:1, 글자 `#FAFAFA` 대 배경 18.11:1. 칩 위 글자색은 Streamlit이 정하므로 칩 글자 대비는 확인 못 함(구현 뒤 캡처로 확인).
  - 8.5-11. 경고 카드 신뢰도 구분: `근거 충분` = 초록 테두리 + 글자 배지 `[근거 충분]`, `더 확인 필요` = 주황 테두리 + 글자 배지 `[더 확인 필요]` + 이유 한 줄. 색만으로 구분하지 않습니다(이모지 금지 원칙 유지, [ui.md](ui.md) 6장). 배지 글자는 `html.escape` 후 넣습니다.
  - 8.5-12. 경고 목록 접기: 지금 경고 상자가 `expanded=True`라 sshd 경고 10건이 약 4,400px를 차지합니다(리뷰 측정값). 고칠 설계: 상자는 접힌 상태로 시작하고, 위에 요약 한 줄 `경고 10건 · 높음 n · 중간 n · 낮음 n · 근거 충분 n · 더 확인 필요 n`을 둡니다. 카드 하나하나도 `st.expander(제목 + 배지)`로 접힘. Suricata 예시는 카드 안에서 한 번 더 접습니다.
  - 8.5-13. 시간 연결 안내 고침(5단계 버그): 지금 상대 파일이 없어도 "패킷 탭에서 강조해 두었습니다"/"로그 탭에서 강조해 두었습니다"가 뜹니다(`app.py`의 `st.info`는 `time_center`만 확인). 고칠 설계: 상대 파일(로그 ↔ 패킷)이 올라가 있고 강조된 번호가 1개 이상일 때만 안내를 띄웁니다. 문구 자체(무엇을 쓸지)는 Weo0o0 결정 대기라 바꾸지 않습니다.
  - 8.5-14. 파일을 빼거나 바꾸면 강조 지우기(5단계 버그): 지금 업로더 `×`로 파일을 빼도 `time_center`, `time_link_from`이 남아 새 파일에 이전 강조 안내가 뜹니다. 고칠 설계: 업로드 파일 이름과 크기로 만든 표시값을 `st.session_state["log_file_id"]`/`["packet_file_id"]`에 두고, 값이 바뀌거나 사라지면 `time_center`, `time_link_from`, 대화·경고 강조(`step7_*_highlights`), 행 선택 기록(`prev_log_rows` 등)을 지웁니다.
- UI 리뷰 반영 완료 확인:
  - 파일 없이 앱을 열면 시나리오 카드 홈이 보이고 `st.stop()`으로 멈추지 않음(AppTest).
  - 파일 없는 상태에서 업로드 칸이 본문 맨 위를 차지하지 않음(사이드바 또는 접힌 상자).
  - `config.toml`에 `[theme]`과 `primaryColor`가 있고 빨강 계열(`#ff4b4b`)이 아님. 위 대비 숫자가 다시 계산해도 같음.
  - 경고 카드: 신뢰도 배지 글자 `[근거 충분]`/`[더 확인 필요]`가 화면 문자열에 있음(색 없이도 구분됨).
  - OpenSSH_2k.log + sshd 연도 입력 → 경고 상자가 접혀 시작하고, 요약 줄의 level별 수 합이 전체 경고 수와 같음. (리뷰 캡처에서 연도 2024일 때 경고 10건, 근거 충분 8, 더 확인 필요 2. 다른 연도 값의 결과는 확인 못 함)
  - dns.cap만 올리고 패킷 행을 고름 → "로그 탭에서 강조해 두었습니다"가 나오지 않음. 로그만 올리고 로그 행을 고름 → "패킷 탭에서 강조해 두었습니다"가 나오지 않음.
  - 두 파일을 올려 행을 고른 뒤 한 파일을 `×`로 빼면 `time_center`가 세션 상태에서 사라지고 안내도 사라짐. 다른 파일로 바꿔도 같음.
- 확인 못 함: 컴포넌트 안 스와이프가 터치 화면에서 동작하는지, `streamlit.components.v2`가 더 맞는지, AppTest로 컴포넌트 반환값을 흉내 내는 방법.
- 기능: 1번(도움 가이드)과 5번(오해 힌트)을 학습용으로 넓힘.

### 9단계 (선택): 공부 노트 내보내기
- 목표: 본 경고, 쓴 필터, 배운 용어를 마크다운으로 저장.
- 새 파일(설계): `elpa/notes.py`.
- 데이터 형식: `StudyNote(file_names, alerts: list[Alert], filters: list[str], terms: list[str], created_at)`. `filters`는 6단계에서 만든 Wireshark 문자열, `terms`는 `help.yaml`에서 "?"로 열어 본 키.
- 9-1. 세션 기록: 필터를 적용하거나 "?"를 누를 때 `st.session_state["note_log"]`에 추가(같은 값은 한 번만).
- 9-2. `render_note(note) -> str`: 마크다운 문자열. 제목, 파일, 경고(msg·근거 번호·신뢰도), 필터, 용어 뜻.
- 9-3. 화면: `st.download_button`으로 `.md` 받기. 파일 내용 원문(로그 줄 전체)은 넣지 않고 번호만 넣음(개인 정보가 노트에 퍼지지 않게).
- 완료 확인 방법: 7단계 확인 뒤 내보낸 노트에 그 경고 `msg`와 6단계에서 쓴 Wireshark 필터 문자열이 들어 있음(문자열 포함 테스트).
- 기능: 6번(공부 노트).

### 10단계 (선택, 나중): Zeek conn.log 읽기
- 목표: Zeek conn.log(TSV/JSON)를 대화 요약 탭에 표시. 간단할 때만.
- 새 파일(설계): `elpa/zeek_reader.py`, 함수 `read_zeek_conn(path) -> tuple[ParseResult, list[Conversation]]`.
- 10-1. 형식 판단: 첫 줄이 `#separator`로 시작하면 TSV, `{`로 시작하면 JSON(한 줄에 하나).
- 10-2. TSV: `#fields` 줄의 이름으로 칸을 맞춤. `-`는 빈 값(`None`).
- 10-3. 대응: `uid` → `uid`(Zeek 값 그대로, 예 `C...` 형태), `proto` → `protocol`(대문자), `service` → `service`, `id.orig_h`+`id.orig_p` → `a`, `id.resp_h`+`id.resp_p` → `b`, `ts` → `start`(3단계와 같은 `...Z` 문자열), `duration`, `orig_pkts + resp_pkts` → `packets`, `orig_ip_bytes + resp_ip_bytes` → `bytes`, `conn_state` → `state`, `history` → `history`. `stream`은 읽은 순서 번호, `packet_numbers`는 빈 튜플(패킷이 없음).
- 10-4. 못 읽은 줄은 `unparsed`/`unparsed_lines`에 넣음(1단계와 같은 규칙).
- 완료 확인 방법: dns.cap을 Zeek로 직접 돌려 만든 conn.log를 올리면 대화 수가 3단계 결과(8개)와 같아야 함. 지금 Zeek 설치·실행 결과는 확인 못 함. 공개 conn.log 샘플도 확인 못 함. `bytes` 정의가 3단계(`len(buf)` 합)와 Zeek(`ip_bytes`)에서 달라 같은 값이 나오는지는 확인 못 함.
- 기능: 7번.

### 11단계 (선택, 나중): Suricata eve.json 경보 읽기
- 목표: `event_type`이 `alert`인 줄을 경고 카드 형식으로 표시. 간단할 때만.
- 새 파일(설계): `elpa/eve_reader.py`, 함수 `read_eve_alerts(path) -> tuple[ParseResult, list[Alert]]`.
- 11-1. 한 줄씩 `json.loads`. 실패한 줄은 `unparsed_lines`에 번호 기록. `event_type != "alert"`인 줄은 세지만 카드로 만들지 않음.
- 11-2. 대응: `alert.signature` → `msg`, `alert.category` → `category`, `alert.severity` → `level`(1 → 높음, 2 → 중간, 3 이상 → 낮음; 숫자와 뜻의 대응은 구현 때 Suricata 문서로 다시 확인), `alert.signature_id`/`rev` → `rule_id`, `src_ip` → `track_value`, `pcap_cnt`(있으면) → `evidence` 패킷 번호, `flow_id`는 상세에 표시.
- 11-3. 신뢰도: 같은 pcap을 함께 올렸고 `pcap_cnt` 번호의 패킷이 실제로 있으면 `근거 충분`, 아니면 `더 확인 필요`.
- 완료 확인 방법: 공개 pcap을 Suricata로 직접 돌려 만든 eve.json의 alert 줄 수(`grep -c '"event_type":"alert"'`)와 카드 수가 같음. 공개 eve.json 샘플, Suricata 설치, `pcap_cnt`가 Wireshark `frame.number`와 같은지는 모두 확인 못 함.
- 기능: 4번.

### 단계 사이 연결 요약
| 단계 | 새 함수(설계) | 다시 쓰는 것 |
|---|---|---|
| 5 | `record_time`, `build_timeline`, `numbers_near` | `Record`, `app.py` 시간 표시 규칙 |
| 6 | `load_filters`, `apply_filters`, `to_wireshark`, `to_tshark`, `to_awk` | 5단계 시간 |
| 7 | `load_rules`, 경고 계산, 힌트 계산 | 5단계 시간, 6단계 조건 |
| 7.5 | `load_layers`, `load_scenarios`, `layer_of`, `scenarios_for`, `build_layer_help` | 4단계 행 선택, 7단계 YAML 읽기 방식 |
| 8 | `table_rows`, `to_csv` | 4단계 표, 6단계 번역 |
| 8.5 | `load_learning`, `card_swiper` | 7·7.5단계 YAML 읽기 방식, 세션 상태 |
| 9 | `render_note` | 6·7단계 결과 |
| 10 | `read_zeek_conn` | `Conversation`, `ParseResult` |
| 11 | `read_eve_alerts` | `Alert`, `ParseResult` |

## 하지 않을 것
- 실시간 캡처, 자동 차단, 대용량 처리, AI 설명, SIEM 연동, Sigma 규칙 변환, 규칙 원문 복사(DRL 등 라이선스 때문).

## 참고
- [analysis/wireshark.md](analysis/wireshark.md)
- [analysis/zeek.md](analysis/zeek.md)
- [analysis/suricata.md](analysis/suricata.md)
- [analysis/log-tools.md](analysis/log-tools.md) (Sigma, Wazuh)
- [analysis/scapy.md](analysis/scapy.md)
- [samples.md](samples.md)
