# 로그 분석 도구 분석: Sigma와 Wazuh

> 앞선 분석: [wireshark.md](wireshark.md) · [zeek.md](zeek.md) · [suricata.md](suricata.md)

이 문서는 두 도구가 로그를 읽고 경고를 만드는 방식을 정리합니다. 그리고 우리 도구가 무엇을 가져오고 무엇을 버릴지 정합니다. 설계만 다루며 코드는 없습니다.

## 용어
- Sigma: 로그 탐지 규칙을 YAML로 적는 공통 형식. 특정 제품에 묶이지 않습니다.
- Wazuh: 로그를 모아 해석하고 경보를 만드는 오픈소스 보안 플랫폼.
- 디코더(decoder): Wazuh에서 로그 한 줄의 글자를 필드로 나누는 설정.
- 정규식(regex): 글자 패턴 규칙. 예를 들어 `(\S+)`는 "공백이 아닌 글자 덩어리 하나"라는 뜻입니다.
- 필드: 로그에서 뽑아낸 이름 붙은 값. 예: `srcip`(출발지 IP), `user`(사용자).
- EventID: Windows 이벤트 종류 번호. 예: 4624는 로그인 성공, 4625는 로그인 실패.
- 오탐(false positive): 문제가 아닌데 경고가 나는 것.
- DRL: Detection Rule License. Sigma 규칙에 붙는 라이선스.

## 1. Sigma

### 입력
- Sigma는 로그를 직접 읽는 프로그램이 아닙니다. 규칙 파일(YAML)이 입력입니다.
- `logsource`가 이 규칙을 적용할 로그 종류를 정합니다. 예: `product: windows`, `service: security` → Windows 보안 이벤트 로그.

### 파싱
- Sigma 규칙은 "로그가 이미 필드로 나뉘어 있다"고 가정합니다. 필드를 나누는 일은 규칙을 실행하는 쪽(SIEM 등)이 합니다.
- 규칙 안의 필드 이름(`EventID`, `IpAddress`)은 Windows 이벤트의 필드 이름과 그대로 맞습니다.

### 해석
실제 규칙 `win_security_susp_failed_logon_source.yml`(공개 IP에서 온 로그인 실패)의 구조입니다. 아래는 원문에서 필요한 부분만 줄인 것입니다.

```yaml
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    filter_main_local_ranges:
        IpAddress|cidr:
            - '10.0.0.0/8'
            - '192.168.0.0/16'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate logon attempts over the internet
level: medium
```

- `detection` 아래에 이름 붙은 조건 묶음(`selection`, `filter_...`)을 만듭니다.
- 같은 묶음 안의 항목은 모두 맞아야 합니다. 한 필드에 값 목록을 주면 그중 하나만 맞으면 됩니다.
- `|cidr` 같은 수식어(modifier)가 비교 방법을 바꿉니다. `cidr`은 IP가 그 범위 안에 있는지 봅니다.
- `condition`은 묶음들을 `and`, `or`, `not`, `1 of 이름_*`로 엮습니다. 위 규칙은 "4625이면서, 사설 IP 범위가 아닐 때"입니다.
- `falsepositives`는 경고가 나도 문제가 아닐 수 있는 경우를 사람 말로 적습니다.
- `level`은 중요도입니다. 위 규칙은 `medium`입니다. (가능한 값 전체 목록은 이번에 명세 원문에서 확인 못 함)

### 표시
- Sigma 자체는 화면이 없습니다. 변환 도구로 다른 제품의 검색어로 바꾼 뒤 그 제품에서 결과를 봅니다.

### 라이선스
- 저장소 LICENSE 파일 원문: Sigma 명세와 로고는 public domain입니다. SigmaHQ 저장소의 규칙은 DRL 1.1입니다.
- 그래서 우리는 규칙 원문을 복사해 넣지 않습니다. 구조만 참고하고, 규칙 파일 링크와 출처를 적습니다. (DRL의 세부 조건은 이번에 원문을 읽지 않아 확인 못 함)

### 가져올 것
- `falsepositives` → 우리 `rules.yaml`의 `오해 주의` 칸.
- `level` → 우리 `level` 칸(높음/중간/낮음).
- `selection` + `condition` 구조 → 우리 규칙의 `조건`을 "이 필드가 이 값" 목록으로 적는 방식.
- `logsource` → 규칙마다 어느 로그 종류(auth.log, access.log, evtx, pcap)에 적용하는지 적는 `대상` 칸.

### 버릴 것
- 다른 제품 검색어로 변환하는 기능. 우리는 우리 레코드에만 적용합니다.
- 수식어 전체. `contains`, `cidr` 정도만 씁니다.

## 2. Wazuh

### 입력
- 에이전트가 보낸 로그 줄. 예: Linux `auth.log`의 sshd 줄.

### 파싱 (디코더)
- 디코더는 XML로 적습니다. 공식 문서 예시에 쓰이는 칸은 다음과 같습니다.
  - `prematch`: 이 디코더가 맡을 줄인지 먼저 확인하는 짧은 패턴.
  - `regex`: 괄호 `( )`로 값을 잡아 냅니다. `offset="after_prematch"`로 prematch 뒤부터 찾게 할 수 있습니다.
  - `order`: 괄호로 잡은 값에 차례대로 필드 이름을 붙입니다. 예: `<order>srcuser</order>`, `<order>id, srcip, dstip</order>`.
  - `parent`: 부모 디코더가 먼저 맞아야 자식 디코더가 돌아갑니다.
- 정리하면, 한 줄 → prematch로 종류 판단 → regex로 값 잡기 → order로 이름 붙이기 순서입니다.

### 해석 (룰)
공식 문서 예시를 바탕으로 정리했습니다.
- `level`: 0~16. 0은 경보를 만들지 않습니다.
- `if_sid`: 앞선 룰(번호)이 맞았을 때만 이 룰을 봅니다. 룰을 사슬처럼 엮습니다.
- `frequency` + `timeframe`: "몇 초 안에 몇 번"입니다. 문서 예시는 다음과 같습니다.
  ```xml
  <rule id="30202" level="10" frequency="10" timeframe="120">
    <if_matched_sid>30201</if_matched_sid>
  ```
  → 룰 30201이 120초 안에 10번 맞으면 level 10 경보를 냅니다.
- `same_srcip`: 셀 때 같은 출발지 IP끼리만 셉니다.
- `ignore`: 경보 뒤 몇 초 동안 다시 울리지 않게 합니다(경보 폭주 방지).
- `description`에 `$(srcip)`처럼 필드 값을 넣을 수 있습니다.

### 표시 (alerts)
- 경보는 JSON으로 남습니다. 문서 예시의 칸은 `rule.level`, `rule.description`, `rule.id`, `rule.firedtimes`, `full_log`(원본 줄), `previous_output`(앞서 셌던 줄들), `decoder.name`, `data`(뽑은 필드)입니다.
- `full_log`와 `previous_output` 덕분에 경보의 근거 원문을 바로 볼 수 있습니다.

### 라이선스
- 저장소 LICENSE 원문 기준으로, 대부분은 GPLv2입니다. 단, `src/engine/`은 AGPL-3.0 이상이고 일부 공유 라이브러리는 GPLv2 또는 AGPL-3.0 중 고를 수 있습니다. "전부 GPLv2"는 아닙니다.
- 우리는 Wazuh 코드나 룰 원문을 넣지 않습니다. 구조만 참고합니다.
- 기본 sshd 룰 파일의 저장소 위치는 이번에 찾지 못해 확인 못 함. 원문을 인용하지 않았습니다.

### 가져올 것
- 디코더 방식 → `decoders.yaml`: 로그 종류마다 `prematch`, `regex`, `fields`(=order) 표.
- `frequency` / `timeframe` / `same_srcip` → 우리 `count` / `seconds` / `track`(이미 Suricata 분석에서 정한 칸과 같은 뜻).
- `ignore` → 같은 경고 중복 억제(Zeek Notice의 identifier+시간과 같은 목적).
- `full_log` + `previous_output` → 경고 카드의 근거 원본 줄 목록.

### 버릴 것
- 에이전트/서버 구조, 대시보드, 이메일 경보, CDB 목록, MITRE 표, 규정 준수 그룹(PCI 등).
- `if_sid` 사슬은 처음에는 쓰지 않습니다. 규칙 하나가 조건을 다 갖게 해서 초보가 읽기 쉽게 합니다.

## 3. 우리 도구 흐름에 반영
| 단계 | Sigma에서 | Wazuh에서 |
|---|---|---|
| 입력 | `logsource`로 대상 로그 종류 명시 | - |
| 파싱 | 필드 이름은 원래 로그 이름 그대로 | prematch → regex → order 표 (`decoders.yaml`) |
| 해석 | selection/condition, level, falsepositives | frequency/timeframe/same_srcip, ignore |
| 표시 | `오해 주의` 문구 | 원본 줄 + 앞서 센 줄 목록 |

## 출처 (이번에 직접 열어 본 것)
- Sigma 저장소: https://github.com/SigmaHQ/sigma
- Sigma 라이선스 파일: https://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE
- Sigma 명세: https://github.com/SigmaHQ/sigma-specification
- DRL 저장소: https://github.com/SigmaHQ/Detection-Rule-License
- 예시 규칙: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml
- Wazuh 저장소와 라이선스: https://github.com/wazuh/wazuh , https://raw.githubusercontent.com/wazuh/wazuh/main/LICENSE
- Wazuh 디코더 문법: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html
- Wazuh 룰 문법: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
