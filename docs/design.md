# easy-log-packet-analyzer 설계 문서

> **설계 단계 완료 (2026-10-30).** 다음: 코드 구현. 1단계부터 차례대로 만들고, 단계마다 아래 '완료 확인 방법'으로 확인합니다.

> 왜 필요한지: [why.md](why.md) · 핵심 기능: [features.md](features.md) · 샘플: [samples.md](samples.md)

대상: 공부하는 취업 준비생. 몇 MB 크기의 공개 샘플 로그와 pcap을 웹 화면에서 보며 기초를 익히고 Wireshark로 넘어가게 돕습니다.
이 문서는 설계만 담습니다. 코드는 없습니다.

## 라이브러리와 환경
- Python 3.11 이상에서 동작합니다.
- 저장소 라이선스는 MIT로 유지합니다.
- pcap 읽기에는 dpkt(BSD 라이선스)를 씁니다. BSD는 MIT와 같은 허용적(permissive) 라이선스라 함께 써도 됩니다.
- dpkt: pcap·pcapng 파일을 읽어 패킷을 계층(이더넷, IP, TCP 등)으로 나눠 주는 Python 라이브러리.
- pcapng 지원이 dpkt에서 제대로 되는지는 확인 못 함.

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
| `help.yaml` | 열·필드 "?" 설명 | - |
| `filters.yaml` | 필터·열 이름 → Wireshark/tshark/zeek-cut/awk 번역 | Wireshark, Zeek |
| `rules.yaml` | 경고 규칙 | Zeek Notice, Suricata, Sigma, Wazuh |
| `hints.yaml` | 초보 오해 힌트 | Zeek Weird |

## 단계
샘플 이름은 [samples.md](samples.md)에 있는 것입니다.

### 1단계: 로그 파일 읽기 (3종)
- 목표: 로그 3종을 레코드로 바꾼다.
- 입력: `auth.log`(sshd 줄), Apache/Nginx `access.log`, Windows `.evtx`.
- 출력: 레코드 목록(원본 줄 번호 포함). 정규식에 안 맞는 줄은 "읽지 못한 줄"로 세어 표시.
- 방법: 텍스트 로그는 `decoders.yaml`의 표를 씁니다. Wazuh 디코더처럼 `prematch`(이 줄이 맞는지 먼저 확인) → `regex`(값 잡기) → `fields`(잡은 값에 차례대로 이름 붙이기) 순서입니다. `.evtx`는 `python-evtx`로 읽고 EventID, 시간, IpAddress, TargetUserName을 뽑습니다.
- `decoders.yaml` 모양(설계 예시):
  | 로그 종류 | prematch | regex (요지) | fields |
  |---|---|---|---|
  | sshd 실패 | `Failed password for` | `for (invalid user )?(.*?) from (\S+) port (\d+)` | `invalid`, `user`, `srcip`, `srcport` |
  | sshd 성공 | `Accepted password for` | `for (\S+) from (\S+) port (\d+)` | `user`, `srcip`, `srcport` |
  | sshd 없는 사용자 | `Invalid user` | `Invalid user (\S*) from (\S+)` | `user`, `srcip` |
  | access.log | (없음, 모든 줄) | `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+)` | `srcip`, `time`, `method`, `path`, `status`, `bytes` |
  - 사용자 이름 앞에 공백이 한 칸 더 있는 줄이 있어서(예: `invalid user  0101`) 사용자 칸은 `\S+`가 아니라 `(.*?)`로 잡습니다.
  - 줄 앞의 시간·호스트·프로그램 이름(`Dec 10 06:55:48 LabSZ sshd[24200]:`)은 공통 앞부분 정규식 하나로 먼저 잘라 냅니다.
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
  | 종류(프로토콜) | 가장 안쪽 계층 이름 (예: DNS) | Raw |
  | TCP 플래그 | TCP `flags` | 빈칸 |
  | 길이 | `len(buf)` | - |
  | 요약 | 계층 이름으로 우리가 만든 한 줄 요약 | - |
  | 원본 | 번호 (상세 보기에서 16진수 덤프와 계층별 필드) | - |
- 오류 처리:
  - pcap이 아닌 파일(`ValueError`) → "pcap 파일이 아닙니다" 안내, 아무것도 표시 안 함.
  - 잘린 파일(`dpkt.dpkt.NeedData`, `dpkt.dpkt.UnpackError`) → 읽은 만큼 표시하고 "파일 끝이 잘려 N개까지만 읽음" 안내.
  - 모르는 링크 타입 → Raw로 읽고 안내.
  - 10MB 초과 → 읽지 않고 안내.
- 완료 확인 방법: dns.cap → 패킷 38개, 모두 종류 DNS, UDP 53번 포트 38개, 1번 요약 `Ethernet / IP / UDP / DNS`, 1번 시간 1112172466.496046(UTC 초). 이 숫자들은 Scapy로 확인했던 값이라 dpkt로는 확인 못 함. 앞 500바이트만 남긴 dns.cap 사본 → 4개 + 잘림 안내. 텍스트 파일 → 오류 안내. (tshark 비교는 tshark 설치 후)
- 기능: 3번, 2번.

### 3단계: 대화(연결) 요약 만들기
- 목표: 패킷을 대화로 묶는다.
- 입력: 2단계 패킷 레코드.
- 방법: dpkt에는 Scapy `sessions()` 같은 대화 묶기 기능이 없어서 직접 만듦. (프로토콜, 작은 쪽 IP:포트, 큰 쪽 IP:포트)로 정렬한 양방향 키로 묶음. Zeek conn.log 방식.
- 번호: 키가 처음 나온 순서대로 0부터 `tcp.stream` / `udp.stream` 번호를 붙임(Wireshark가 0부터 처음 본 순서로 매긴다고 보고 맞춤. tshark로 실제 비교는 확인 못 함, 구현 때 확인). uid는 우리 도구용 고유 문자열.
- 출력: 대화 레코드(uid, stream 번호, 시작 시각, 지속 시간, 패킷 수, 바이트 수, 상태, history 비슷한 흐름 글자).
- 범위: TCP 재조립은 하지 않음(dpkt는 TCP 재조립을 기본으로 하지 않음).
- 완료 확인 방법: dns.cap → 대화 8개, 가장 큰 대화 192.168.170.8:32795 ↔ 192.168.170.20:53 = 24패킷. 두 숫자 모두 Scapy로 확인한 값이라 dpkt로는 확인 못 함. tshark가 있으면 `tshark -r dns.cap -q -z conv,udp` 대화 수와 같아야 함.
- 기능: 7번(대화 요약 탭).

### 4단계: 웹 화면 기본 (Streamlit)
- 목표: 파일을 올리고 탭에서 표로 본다.
- 입력: 1~3단계 레코드.
- 출력: 로그 탭, 패킷 탭, 대화 요약 탭. 대화 한 줄을 누르면 패킷 탭에서 그 uid의 패킷 강조. 열·필드마다 "?" 도움말(`help.yaml`).
- 완료 확인 방법: OpenSSH_2k.log와 dns.cap을 올리면 세 탭에 각각 2,000줄, 38줄(dpkt 확인 못 함), 3단계 대화 수만큼 보인다. "?"를 누르면 `help.yaml` 문구가 나온다.
- 기능: 1번(도움 가이드), 3번, 7번.

### 5단계: 시간 연결 보기
- 목표: 한 탭에서 고른 시각의 앞뒤 몇 초를 다른 탭에서 강조.
- 입력: 고른 레코드, 시간대 설정(로그는 현지 시간, pcap은 UTC 등).
- 출력: 강조 표시.
- 완료 확인 방법: 공개 샘플 중 로그와 pcap이 같은 시간대인 것은 확인 못 함. 그래서 OpenSSH_2k.log에서 시간대 설정을 +9로 바꾸면 표시 시간이 정확히 9시간 바뀌는지, 같은 파일 안에서 고른 줄 앞뒤 범위가 강조되는지 확인.
- 기능: 3번.

### 6단계: 필터와 Wireshark 명령 번역
- 목표: 클릭 필터(IP, 포트, 프로토콜, 시간)와 같은 뜻의 Wireshark 필터·tshark 명령을 옆에 보여 준다.
- 입력: 고른 필터 조건, `filters.yaml`.
- 출력: 걸러진 표 + 명령 문자열.
- 완료 확인 방법: dns.cap에서 "포트 53"을 누르면 표 줄 수가 `tshark -r dns.cap -Y "udp.port == 53 || tcp.port == 53" | wc -l` 결과와 같다. apache_logs에서 "상태 404"는 213줄.
- 기능: 2번(가장 중요).

### 7단계: 규칙 기반 경고 카드와 오해 힌트
- 목표: `rules.yaml` 규칙으로 경고 카드를, `hints.yaml`로 오해 힌트를 만든다. AI 사용 안 함.
- 입력: 레코드, `rules.yaml`, `hints.yaml`.
- 출력: 경고 카드(왜 이상한가, 근거 원본 줄/패킷, 다음 확인 단계, Wireshark 필터, 읽기 전용 Suricata 룰 예시, 신뢰도).
- `rules.yaml` 칸:
  | 칸 | 뜻 | 참고 |
  |---|---|---|
  | `id`, `version` | 고유 번호, 고친 횟수 | Suricata sid/rev |
  | `대상` | 적용할 로그 종류(auth.log, access.log, evtx, pcap) | Sigma logsource |
  | `조건` | "이 필드가 이 값" 목록. 모두 맞아야 함 | Sigma selection |
  | `count`, `seconds`, `track`, `unique` | 몇 초 안에 몇 번, 누구 기준으로, 서로 다른 값 세기 | Suricata threshold, Wazuh frequency/timeframe/same_srcip |
  | `중복 억제` | 같은 경고를 몇 초 동안 다시 안 냄 | Zeek Notice identifier, Wazuh ignore |
  | `level` | 높음/중간/낮음 | Sigma level, Wazuh level |
  | `category` | 쉬운 한국어 분류(예: 정찰 시도) | Suricata classtype |
  | `msg`, `왜 이상한가`, `다음 단계`, `wireshark_filter` | 카드 문구 | Zeek Notice |
  | `오해 주의` | 경고가 나도 문제가 아닐 수 있는 경우 | Sigma falsepositives |
  | `suricata_example` | 참고용 룰 텍스트, 실행 안 함 | Suricata |
- 카드의 근거: Wazuh `full_log`/`previous_output`처럼, 셌던 줄을 모두 목록으로 보여 줍니다. 패킷은 `frame.number == N`.
- 신뢰도 표시: 근거를 하나씩 다시 확인해 맞는 것만 인정한다는 생각을 따릅니다(cloudflare/security-audit-skill의 "independently verified findings" 방식, https://github.com/cloudflare/security-audit-skill).
  - `근거 충분`: 조건이 모두 맞고, 근거 줄이 `count` 이상 있고, 그 줄을 원본에서 다시 찾을 수 있음.
  - `더 확인 필요`: 일부 필드가 비었거나(읽지 못한 줄 포함), 근거가 `count`에 겨우 맞거나, `오해 주의`에 적은 경우에 해당할 수 있음.
- "특이하지만 공격 아님"(재전송, RST, DNS 실패 등)은 경고가 아니라 `hints.yaml` 힌트로 표시.
- 완료 확인 방법: OpenSSH_2k.log에 "같은 출발지 IP의 sshd 실패가 60초 안에 5번 이상" 규칙을 걸면 출발지 IP 9개에 경고 카드가 나오고(가장 많은 것은 183.62.140.253, 실패 286줄), 근거 줄을 눌렀을 때 원본 줄 번호가 `grep -n` 결과와 같다. 카드에 `level`, `오해 주의`, 신뢰도가 보인다.
- 기능: 4번(경고 카드), 5번(오해 힌트).

### 8단계: 열 고르기와 내보내기
- 목표: 보고 싶은 열만 골라 보고 CSV로 내보낸다.
- 입력: 탭의 레코드, 고른 열(세션에 저장), 시간대 설정(5단계 재사용).
- 출력: 고른 열만 있는 표와 CSV, 같은 일을 하는 명령. 패킷은 tshark `-T fields -e ...`, Zeek 로그는 `zeek-cut`, 텍스트 로그는 `awk`. 번역은 `filters.yaml`(예: 출발지 IP → `ip.src` / `id.orig_h` / access.log 1번 칸).
- 완료 확인 방법: apache_logs에서 출발지 IP와 상태 코드만 골라 CSV로 내보낸 결과가 화면에 나온 `awk '{print $1","$9}'` 결과와 같다. dns.cap에서도 같은 방식으로 tshark 결과와 비교.
- 기능: 8번.

### 9단계 (선택): 공부 노트 내보내기
- 목표: 본 경고, 쓴 필터, 배운 용어를 마크다운으로 저장.
- 입력: 세션 기록. 출력: `.md` 파일.
- 완료 확인 방법: 7단계 확인 뒤 내보낸 노트에 그 경고 msg와 6단계에서 쓴 Wireshark 필터가 들어 있다.
- 기능: 6번(공부 노트).

### 10단계 (선택, 나중): Zeek conn.log 읽기
- 목표: Zeek conn.log(TSV/JSON)를 대화 요약 탭에 표시. 간단할 때만.
- 입력: conn.log. 출력: 3단계와 같은 대화 레코드.
- 완료 확인 방법: dns.cap을 Zeek로 직접 돌려 만든 conn.log를 올리면 대화 수가 3단계 결과와 같다. (공개 conn.log 샘플은 확인 못 함)
- 기능: 7번.

### 11단계 (선택, 나중): Suricata eve.json 경보 읽기
- 목표: `event_type`이 `alert`인 줄을 경고 카드 형식으로 표시. 간단할 때만.
- 입력: eve.json. 출력: 경고 카드(signature → msg, category, severity → level, `pcap_cnt` → 패킷 번호).
- 완료 확인 방법: 공개 pcap을 Suricata로 직접 돌려 만든 eve.json의 alert 줄 수와 카드 수가 같다. (공개 eve.json 샘플은 확인 못 함)
- 기능: 4번.

## 하지 않을 것
- 실시간 캡처, 자동 차단, 대용량 처리, AI 설명, SIEM 연동, Sigma 규칙 변환, 규칙 원문 복사(DRL 등 라이선스 때문).

## 참고
- [analysis/wireshark.md](analysis/wireshark.md)
- [analysis/zeek.md](analysis/zeek.md)
- [analysis/suricata.md](analysis/suricata.md)
- [analysis/log-tools.md](analysis/log-tools.md) (Sigma, Wazuh)
- [analysis/scapy.md](analysis/scapy.md)
- [samples.md](samples.md)
