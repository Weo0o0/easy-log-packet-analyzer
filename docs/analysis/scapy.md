# 패킷 라이브러리 분석: Scapy

> 이 문서는 분석 기록입니다. 프로젝트는 Scapy 대신 dpkt(BSD)를 쓰기로 했습니다. 그래서 아래 GPL 라이선스 우려는 해당 없음.

> 앞선 분석: [wireshark.md](wireshark.md) · [zeek.md](zeek.md) · [suricata.md](suricata.md) · [log-tools.md](log-tools.md)

Scapy는 우리 도구가 pcap을 읽을 때 쓸 Python 라이브러리입니다. 이 문서는 Scapy가 pcap을 어떻게 읽고 패킷을 어떻게 나누는지 정리합니다. 우리는 **읽기만** 합니다. 패킷을 만들거나 보내는 기능은 다루지 않습니다. 설계만 다루며 코드는 없습니다.

## 용어
- pcap: 캡처한 패킷을 저장한 파일 형식. pcapng는 그 새 버전입니다.
- 계층(layer): 패킷 안에 겹겹이 들어 있는 프로토콜 한 칸. 예를 들어 Ether(이더넷) 안에 IP, 그 안에 UDP, 그 안에 DNS가 들어 있습니다.
- 페이로드(payload): 한 계층의 머리(헤더) 뒤에 붙은 나머지 바이트. 다음 계층이 여기서 나옵니다.
- 디섹터(dissector): Wireshark에서 바이트를 프로토콜 필드로 해석하는 코드.
- 스트리밍 읽기: 파일 전체를 메모리에 올리지 않고 패킷을 하나씩 읽고 버리는 방식.
- 링크 타입(linktype): pcap 파일 머리에 적힌 "맨 아래 계층이 무엇인지"를 나타내는 번호(예: 이더넷).

## 버전과 라이선스
- 이번 확인에 쓴 버전: scapy 2.8.0 (Mac mini 임시 venv에 설치해 확인).
- 라이선스: 저장소 LICENSE 파일 첫 줄이 "GNU GENERAL PUBLIC LICENSE Version 2"입니다.
- 우리 저장소에 Scapy 코드를 복사하지 않습니다. 라이브러리로 설치해서 쓸 계획입니다. GPL 라이브러리를 쓰는 우리 코드의 라이선스 영향은 이번에 따로 확인 못 함(구현 전에 확인할 일).

## 1. 입력: pcap을 읽는 세 가지 방법
| 방법 | 하는 일 | 메모리 |
|---|---|---|
| `rdpcap(파일)` | 모든 패킷을 읽어 목록(PacketList)으로 돌려줌 | 파일 전체가 메모리에 올라감 |
| `PcapReader(파일)` | 패킷을 하나씩 꺼내 줌 (`for pkt in reader`) | 한 번에 패킷 하나 |
| `sniff(offline=파일)` | 원래는 실시간 캡처 함수. `offline=`을 주면 파일을 읽음. `session=`, `prn=`(패킷마다 부를 함수), `store=False`(목록에 안 쌓기)를 함께 씀 | `store=False`면 적음 |

- 소스 확인: `rdpcap`은 안에서 `with PcapReader(filename) as fdesc: return fdesc.read_all(count=count)`를 합니다. 즉 rdpcap = PcapReader로 전부 읽기입니다. docstring에 "pcap or pcapng"를 읽는다고 적혀 있습니다.
- `PcapReader`는 파일 머리의 링크 타입 번호로 맨 아래 계층 클래스(예: Ether)를 고릅니다. 모르는 번호면 경고를 내고 Raw(해석 안 된 바이트)로 읽습니다.

## 2. 파싱: 패킷이 계층으로 나뉘는 방식
- 모든 계층은 `Packet` 클래스를 이어받은 클래스입니다(Ether, IP, TCP, UDP, DNS 등).
- 각 클래스의 `fields_desc`가 필드 목록입니다. 필드마다 이름, 기본값, 바이트 크기와 형식이 정해져 있습니다. 예(문서): `ShortEnumField("sport", 53, UDP_SERVICES)` → 2바이트, 이름 sport, 숫자에 서비스 이름표를 붙임.
- 바이트를 읽을 때는 `fields_desc` 순서대로 앞에서부터 잘라 각 필드 값을 채웁니다. 남은 바이트가 페이로드입니다.
- 다음 계층 고르기:
  - `bind_layers(아래, 위, 필드=값)`이 "아래 계층의 이 필드가 이 값이면 다음은 위 계층"이라는 규칙을 `payload_guess` 목록에 넣습니다.
  - `guess_payload_class()`가 그 목록을 돌며 필드 값이 모두 맞는 첫 클래스를 고릅니다. 없으면 기본 클래스(보통 Raw)를 씁니다.
  - 실제 소스(`scapy/layers/inet.py`): `bind_layers(Ether, IP, type=2048)`, `bind_layers(IP, TCP, frag=0, proto=6)`, `bind_layers(IP, UDP, frag=0, proto=17)`.
- 그래서 Ether/IP/TCP는 이렇게 쌓입니다: Ether의 type이 2048(0x0800) → IP. IP의 proto가 6이고 조각(frag)이 0 → TCP. TCP 포트 값 → 그 위 프로토콜(있으면).
- `frag=0` 조건 때문에 IP 조각 중 첫 조각이 아닌 것은 TCP/UDP로 해석되지 않습니다(소스 조건에서 읽은 내용, 실제 조각 pcap으로는 확인 못 함).

## 3. 해석: 계층과 필드 꺼내기
- `pkt[IP].src`: IP 계층의 src 필드. 계층이 없으면 오류가 나므로 먼저 확인합니다.
- `pkt.haslayer(DNS)` 또는 `DNS in pkt`: 그 계층이 있는지 True/False.
- `pkt.time`: 캡처 시각. 1970-01-01 UTC부터 센 초(소수 포함). 2.8.0에서는 실제 타입이 `EDecimal`(Scapy의 소수 타입)이었습니다. dns.cap 1번 패킷: `1112172466.496046`.
- `pkt.summary()`: 한 줄 요약. dns.cap 1번: `Ether / IP / UDP / DNS Qry b'google.com.'`.
- `PacketList.sessions()`: 패킷을 묶습니다. 소스 기본 묶음 기준은 `"UDP 출발IP:포트 > 목적IP:포트"` 같은 문자열입니다. **방향별**로 따로 묶입니다(요청과 응답이 다른 묶음).
- `TCPSession`(`sniff(session=TCPSession)`): TCP 조각을 이어 붙입니다. 소스 주석: "`tcp_reassemble` 함수가 있는 프로토콜만" 처리합니다. 문서가 적은 지원 목록: HTTP 1.0, TLS, Kerberos, LDAP, SMB, DCE/RPC, Postgres, DOIP 등. Wireshark처럼 모든 TCP 흐름을 다시 맞추는 것은 아닙니다.

## 4. 표시
- `pkt.show()`: 계층별로 모든 필드를 들여쓰기로 보여 줌.
- `pkt.summary()`: 한 줄.
- `hexdump(pkt)`: 16진수 + 글자 표(Wireshark 아래 칸과 비슷).
- `pkt.pdfdump()`: 계층 그림을 PDF로. PyX 라이브러리가 필요합니다(문서: "Can't import PyX. Won't be able to use psdump() or pdfdump()").

## 5. Wireshark 디섹터와 비교
| | Scapy | Wireshark |
|---|---|---|
| 다음 계층 고르기 | `bind_layers` 규칙 + `guess_payload_class` | 디섹터 테이블 등록(예: 포트 번호) + 휴리스틱 디섹터 |
| 필드 정의 | 클래스의 `fields_desc` | 디섹터가 등록한 필드(hf) |
| 응용 계층 | 있는 것만 해석, 나머지는 Raw | 훨씬 많은 프로토콜 (정확한 수는 확인 못 함) |
| TCP 재조립 | 일부 프로토콜만 | 기본 기능 |
| 패킷 번호 | 없음 (목록 위치는 0부터) | `frame.number` 1부터 |
| 대화 번호 | 없음 | `tcp.stream`, `udp.stream` |

## 6. 초보에게 주의할 점
- 속도: 순수 Python이라 큰 pcap은 느립니다. 정확한 속도는 이번에 재지 않아 확인 못 함. 그래서 우리 도구는 파일 크기 제한을 둡니다.
- 응용 계층 해석이 Wireshark보다 적어서 Wireshark에서는 보이는 프로토콜 이름이 Scapy에서는 Raw로 보일 수 있습니다.
- 시간은 소수 초(UTC 기준)입니다. 화면에는 사람이 읽는 시각으로 바꾸고 시간대를 맞춰야 합니다.
- 번호: Python 목록 위치는 0부터, Wireshark `frame.number`는 1부터입니다. 우리 도구는 1부터 세어 Wireshark와 맞춥니다.
- `sessions()`는 방향별이라 요청과 응답이 두 묶음으로 나옵니다. Wireshark 대화(Conversation)와 수가 다릅니다.

## 7. 우리 도구에 가져올 것 / 버릴 것
가져올 것
- `PcapReader` 스트리밍 읽기 (메모리 절약).
- `haslayer` / `pkt[계층].필드`로 레코드 필드 채우기.
- `summary()` → 레코드 `요약` 칸.
- `hexdump` → 패킷 상세 보기의 원본 바이트 칸 (Wireshark 아래 칸 설명과 연결).

버릴 것
- `sessions()` 그대로 쓰기 (방향별이라 대화 요약과 안 맞음) → 양방향 키를 우리가 만듦.
- `TCPSession` 재조립 (일부 프로토콜만, 초보 도구 범위 밖).
- `pdfdump` (추가 라이브러리 필요).
- 패킷 만들기·보내기·실시간 캡처 기능 전부.

## 8. 직접 확인한 결과 (Mac mini, 임시 venv, scapy 2.8.0, 저장소 밖에서 실행 후 삭제)
- dns.cap: `rdpcap` 38개, `PcapReader` 38개. 모두 맨 위 계층이 DNS(38개), UDP 53번 포트 38개.
- `sessions()` 결과 16묶음(방향별). 방향을 합치면 대화 8개.
- 앞 500바이트만 남긴 잘린 파일: 오류 없이 4개를 읽고 "Pcap: packet has been truncated" 경고만 냄.
- pcap이 아닌 파일: `Scapy_Exception: Not a supported capture file`.
- tshark가 Mac mini에 없어 Wireshark 쪽 숫자(`frame.number`, `udp.stream`)와 직접 비교는 확인 못 함.

## 출처 (이번에 직접 열어 본 것)
- 저장소: https://github.com/secdev/scapy
- 라이선스: https://raw.githubusercontent.com/secdev/scapy/master/LICENSE
- 사용법 문서: https://scapy.readthedocs.io/en/latest/usage.html
- 계층 만들기 문서(fields_desc, guess_payload_class): https://scapy.readthedocs.io/en/latest/build_dissect.html
- 소스: `scapy/utils.py`(rdpcap, PcapReader), `scapy/packet.py`(guess_payload_class, bind_layers), `scapy/plist.py`(sessions), `scapy/sessions.py`(TCPSession), `scapy/layers/inet.py`(bind_layers 예) — https://github.com/secdev/scapy/tree/master/scapy
- Wireshark 디섹터 문서: https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html
