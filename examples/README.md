# 예시 파일

학습 화면의 `이 예시로 분석해 보기`가 읽는 저장소 번들 파일입니다. 앱은 이 파일들을 수정하지 않고 읽기만 합니다.

| 파일 | 구분 | 출처 | 라이선스 |
|---|---|---|---|
| `apache_logs/apache_logs` | 실제 기록 | elastic/examples 커밋 `6d86454ebb7a850bcd7e80abe86fe683370018a6` | Apache-2.0 |
| `apache_logs/LICENSE` | 실제 기록 부속 (라이선스 전문) | elastic/examples 같은 커밋의 LICENSE | Apache-2.0 |
| `apache_logs/SOURCE.md` | 실제 기록 부속 (출처 설명) | 이 저장소에서 작성 | Apache-2.0 (대상 파일 기준) |
| `ssh_repeated_fail/auth.log` | 교육용 예시 | `tools/make_examples.py`로 생성 (문서용 IP만 사용) | MIT (이 저장소) |
| `dns_query_answer/dns_query_answer.pcap` | 교육용 예시 | `tools/make_examples.py`로 생성 (문서용 IP만 사용) | MIT (이 저장소) |
| `udp_one_side/udp_one_side.pcap` | 교육용 예시 | `tools/make_examples.py`로 생성 (문서용 IP만 사용) | MIT (이 저장소) |
| `README.md` | 교육용 예시 (이 문서) | 이 저장소에서 작성 | MIT (이 저장소) |

합성 파일은 `python tools/make_examples.py [out_dir]`로 다시 만들 수 있고, 실행할 때마다 같은 바이트가 나옵니다. 합성 파일의 주소는 문서용 IP(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)와 example.com 계열 도메인만 씁니다.
