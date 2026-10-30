# 공개 샘플 데이터

단계마다 쓸 공개 샘플입니다. 링크는 모두 2026-10-30에 직접 열어 확인했습니다(HTTP 200). 숫자는 이번에 직접 세어 본 값입니다.
개인/회사 데이터는 넣지 않습니다. 샘플 파일은 저장소에 복사하지 않고 링크만 적습니다.

| 이름 | 종류 | 쓰는 단계 | 링크 | 라이선스/이용 조건 | 직접 센 값 |
|---|---|---|---|---|---|
| OpenSSH_2k.log (loghub) | Linux sshd 로그(auth.log 형식) | 1, 4, 5, 7 | https://github.com/logpai/loghub/tree/master/OpenSSH | 연구·학습 목적으로 자유 이용, 배포 시 저장소 링크와 논문 인용 요청 (README 원문) | 2,000줄, `Failed password` 520줄 |
| apache_logs (elastic/examples) | Apache access.log | 1, 6, 8 | https://github.com/elastic/examples/tree/master/Common%20Data%20Formats/apache_logs | 저장소 라이선스 Apache-2.0 (GitHub API 표시) | 10,000줄, 상태 코드 404가 213줄 |
| security.evtx (python-evtx 테스트 데이터) | Windows 보안 이벤트 로그 | 1 | https://github.com/williballenthin/python-evtx/tree/master/tests/data | 저장소 라이선스 Apache-2.0. 파일 출처는 readme에 "Carlos Dias, via email". 파일 자체의 별도 조건은 확인 못 함 | EventID 4624가 583건, 4625는 0건 |
| dns.cap (Wireshark SampleCaptures) | pcap | 2, 3, 5, 6, 8 | https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap (목록: https://wiki.wireshark.org/SampleCaptures) | 위키 원본 내용은 GNU GPL (https://wiki.wireshark.org/License). 첨부 파일마다 다를 수 있음 | 패킷 38개 |
| Security Repo | 여러 보안 로그 모음 (예비) | 예비 | https://www.secrepo.com/ | CC BY 4.0 (사이트 원문, 예외는 따로 표기) | 개별 파일은 이번에 못 열어 확인 못 함 |

## 빈 곳
- 4625(로그인 실패)가 들어 있는 공개 .evtx: 위 security.evtx에는 없습니다. 공격 재현 샘플 모음은 "공격 내용 넣지 않기" 원칙 때문에 고르지 않았습니다. 다른 공개 샘플은 확인 못 함.
- 로그와 pcap이 같은 시간대에 함께 있는 공개 샘플: 확인 못 함. 그래서 4단계(시간 연결) 확인에는 시간대 설정 동작만 봅니다.
- 공개 Suricata eve.json 샘플: 확인 못 함. 11단계(선택)는 공개 pcap을 Suricata로 직접 돌려 만든 파일로 확인합니다.
