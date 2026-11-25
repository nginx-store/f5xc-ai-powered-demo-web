# F5 XC AI-Powered WAF 데모

동일한 OWASP Juice Shop 오리진 앞에 둔 **F5 Distributed Cloud(XC) AI-Powered WAF**와
**시그니처 전용 Basic WAF**를 비교하는 단일 파일 트래픽 Client입니다.

고정된 데모 시나리오 — 실제 익스플로잇 5개 + 공격처럼 보이는 정상 요청 5개 — 를
두 개의 F5 XC 로드밸런서에 재생하고, 각 WAF별로 True Positive(차단한 공격)와
False Positive(잘못 차단한 정상 요청)를 집계합니다.

> **랩 / 격리 환경 전용.** 모든 payload는 통제된 WAF 뒤의 일회용 OWASP Juice Shop
> 인스턴스를 대상으로 합니다. 테스트 권한이 없는 시스템에 사용하지 마세요.

## 설치

```bash
pip install flask requests
```

## 실행

**대시보드** (Flask, 5000 포트):

```bash
python3 waf_demo.py serve
```

`http://localhost:5000` 접속 → 두 WAF URL(AI-Powered, Basic) 입력 → **Run demo** 클릭.
결과는 WAF별로 분리(TP / FP / FN / TN)되어 전체 요청/응답 증거와 함께 표시됩니다.

**CLI 클라이언트**:

```bash
# Dry run — 요청만 출력, 전송 안 함
python3 waf_demo.py --scenario demo --dry-run

# F5 XC AI-Powered WAF 데모

동일한 OWASP Juice Shop 오리진 앞에 둔 **F5 Distributed Cloud(XC) AI-Powered WAF**와
**시그니처 전용 Basic WAF**를 비교하는 단일 파일 트래픽 하네스입니다.

고정된 데모 시나리오 — 실제 익스플로잇 5개 + 공격처럼 보이는 정상 요청 5개 — 를
두 개의 F5 XC 로드밸런서에 재생하고, 각 WAF별로 True Positive(차단한 공격)와
False Positive(잘못 차단한 정상 요청)를 집계합니다.

> **랩 / 격리 환경 전용.** 모든 payload는 통제된 WAF 뒤의 일회용 OWASP Juice Shop
> 인스턴스를 대상으로 합니다. 테스트 권한이 없는 시스템에 사용하지 마세요.

## 설치

```bash
pip install flask requests
```

## 실행

**대시보드** (Flask, 5000 포트):

```bash
python3 waf_demo.py serve
```

`http://localhost:5000` 접속 → 두 WAF URL(AI-Powered, Basic) 입력 → **Run demo** 클릭.
결과는 WAF별로 분리(TP / FP / FN / TN)되어 전체 요청/응답 증거와 함께 표시됩니다.

**CLI 클라이언트**:

```bash
# Dry run — 요청만 출력, 전송 안 함
python3 waf_demo.py --scenario demo --dry-run

# Live — 한 WAF로 전송, 라벨링 결과를 JSONL로 기록
python3 waf_demo.py --scenario demo --base http://<waf-host> --jsonl out.jsonl
```

## 데모 시나리오

**실제 공격 5개** (Juice Shop에서 동작 검증된 익스플로잇):

| 이름 | 기법 |
|---|---|
| `j_sqli_login` | SQLi 로그인 우회 (`' OR 1=1--`) → 유효한 JWT 발급 |
| `j_sqli_dump` | UNION SQLi → 사용자 이메일 + 패스워드 해시 덤프 |
| `j_sqli_like_bypass` | `LIKE` 기반 Boolean SQLi (저정확도 시그니처) → 전체 행 반환 |
| `j_xss_img` | 반사형 XSS (`<img src=x onerror=...>`) |
| `j_trav_pkg` | 널바이트 Path Traversal (`...%2500.md`) → 백업 파일 읽기 |

**공격처럼 보이는 정상 요청 5개**: `console.*`를 포함한 상품검색 3개
(Medium 정확도 XSS 시그니처를 유발) + 평범한 검색 2개.
  Ran 1 shell command

Repo 비어있고 PUBLIC임. waf_demo.py엔 내부 랩 호스트명(ai-risk/ai-defense.nginxstore.co.kr)과 익스 payload 들어있음 — 공개됨. 진행.



```bash
pip install flask requests
```

## Run

**Dashboard** (Flask, port 5000):

```bash
python3 waf_demo.py serve
```

Open `http://localhost:5000`, enter the two WAF URLs (AI-Powered and Basic), and click
**Run demo**. Results are split per WAF (TP / FP / FN / TN) with full request/response evidence.

**CLI client**:

```bash
# Dry run — print the requests, send nothing
python3 waf_demo.py --scenario demo --dry-run

# Live — send to one WAF, write labeled results to JSONL
python3 waf_demo.py --scenario demo --base http://<waf-host> --jsonl out.jsonl
```

## Demo scenario

**5 real attacks** (verified exploits against Juice Shop):

| name | technique |
|---|---|
| `j_sqli_login` | SQLi login bypass (`' OR 1=1--`) → returns a valid JWT |
| `j_sqli_dump` | UNION SQLi → dumps user emails + password hashes |
| `j_sqli_like_bypass` | Boolean SQLi via `LIKE` (low-accuracy signature) → forces all rows |
| `j_xss_img` | Reflected XSS (`<img src=x onerror=...>`) |
| `j_trav_pkg` | Path traversal with null-byte (`...%2500.md`) → reads a backup file |

**5 benign requests** that look like attacks: 3 product searches containing `console.*`
(which trip a Medium-accuracy XSS signature) + 2 clean searches.

## The point

- **High-impact exploits are blocked by both WAFs** — F5's built-in signatures are strong.
- The AI-Powered WAF's real edge shows in two places:
  1. **`j_sqli_like_bypass`** uses a low-accuracy signature that a default signature-only
     policy lets through; the AI WAF's ML classifier still blocks it.
  2. **False-positive reduction** — the `console.*` searches are legitimate, but a
     signature-only WAF false-blocks them. The AI WAF scores them benign and allows them.

Typical result:

| WAF | TP (attacks blocked) | FP (benign blocked) |
|---|---|---|
| AI-Powered | 5 / 5 | 0 / 5 |
| Basic (signature-only) | 4 / 5 | 3 / 5 |

## Configuration notes

To reproduce the asymmetry, the two F5 XC load balancers are configured differently:

- **AI LB** — Security Policy = Custom, signature accuracy High/Medium/Low all Block,
  Enhance with AI = Enable, Action by Risk Score = Mitigate High + Medium.
- **Basic LB** — Security Policy = Default, Enhance with AI = Disable.

로컬 파일: /root/XC_ALL_SESSIONS/f5-ai-waf-demo/README.md (이미 nginx-store main에 push됨). 직접 할거면 그대로 쓰거나 고쳐 쓰면 됨.

Baked for 16s · done 10:03 AM

❯ 한국어로 해주세요~

README 한국어판:

# F5 XC AI-Powered WAF 데모

동일한 OWASP Juice Shop 오리진 앞에 둔 **F5 Distributed Cloud(XC) AI-Powered WAF**와
**시그니처 전용 Basic WAF**를 비교하는 단일 파일 트래픽 하네스입니다.

고정된 데모 시나리오 — 실제 익스플로잇 5개 + 공격처럼 보이는 정상 요청 5개 — 를
두 개의 F5 XC 로드밸런서에 재생하고, 각 WAF별로 True Positive(차단한 공격)와
False Positive(잘못 차단한 정상 요청)를 집계합니다.

> **랩 / 격리 환경 전용.** 모든 payload는 통제된 WAF 뒤의 일회용 OWASP Juice Shop
> 인스턴스를 대상으로 합니다. 테스트 권한이 없는 시스템에 사용하지 마세요.

## 설치

```bash
pip install flask requests
```

## 실행

**대시보드** (Flask, 5000 포트):

```bash
python3 waf_demo.py serve
```

`http://localhost:5000` 접속 → 두 WAF URL(AI-Powered, Basic) 입력 → **Run demo** 클릭.
결과는 WAF별로 분리(TP / FP / FN / TN)되어 전체 요청/응답 증거와 함께 표시됩니다.

**CLI 클라이언트**:

```bash
# Dry run — 요청만 출력, 전송 안 함
python3 waf_demo.py --scenario demo --dry-run

# Live — 한 WAF로 전송, 라벨링 결과를 JSONL로 기록
python3 waf_demo.py --scenario demo --base http://<waf-host> --jsonl out.jsonl
```

## 데모 시나리오

**실제 공격 5개** (Juice Shop에서 동작 검증된 익스플로잇):

| 이름 | 기법 |
|---|---|
| `j_sqli_login` | SQLi 로그인 우회 (`' OR 1=1--`) → 유효한 JWT 발급 |
| `j_sqli_dump` | UNION SQLi → 사용자 이메일 + 패스워드 해시 덤프 |
| `j_sqli_like_bypass` | `LIKE` 기반 Boolean SQLi (저정확도 시그니처) → 전체 행 반환 |
| `j_xss_img` | 반사형 XSS (`<img src=x onerror=...>`) |
| `j_trav_pkg` | 널바이트 Path Traversal (`...%2500.md`) → 백업 파일 읽기 |

**공격처럼 보이는 정상 요청 5개**: `console.*`를 포함한 상품검색 3개
(Medium 정확도 XSS 시그니처를 유발) + 평범한 검색 2개.

## 핵심

- **고임팩트 익스플로잇은 두 WAF 모두 차단** — F5 내장 시그니처가 강력함.
- AI-Powered WAF의 실질적 우위는 두 군데서 드러남:
  1. **`j_sqli_like_bypass`** 는 기본 시그니처 전용 정책이 통과시키는 저정확도
     시그니처를 사용함. AI WAF의 ML 분류기는 그래도 차단함.
  2. **오탐 감소** — `console.*` 검색은 정상이지만 시그니처 전용 WAF는 오차단함.
     AI WAF는 benign으로 점수화해 통과시킴.

일반적인 결과:

| WAF | TP (차단한 공격) | FP (오차단한 정상) |
|---|---|---|
| AI-Powered | 5 / 5 | 0 / 5 |
| Basic (시그니처 전용) | 4 / 5 | 3 / 5 |

## 설정 참고

이 차이를 재현하려면 두 F5 XC 로드밸런서를 다르게 설정함:

- **AI LB** — Security Policy = Custom, 시그니처 정확도 High/Medium/Low 모두 Block,
  Enhance with AI = Enable, Action by Risk Score = Mitigate High + Medium.
- **Basic LB** — Security Policy = Default, Enhance with AI = Disable.
