# Where to patch first

**payments-service** needs a patch before the next feature release. **fraud-service** can wait for the next release.

## When to patch

| Decision | When |
|----------|------|
| ![Immediate](https://img.shields.io/badge/Immediate-b91c1c?style=flat-square) | Act now |
| ![Out-of-Cycle](https://img.shields.io/badge/Out--of--Cycle-c2410c?style=flat-square) | Security patch, ahead of the feature release |
| ![Scheduled](https://img.shields.io/badge/Scheduled-a16207?style=flat-square) | Next planned release |
| ![Defer](https://img.shields.io/badge/Defer-15803d?style=flat-square) | Track. No patch this cycle |

| Application | Decision | CVEs |
|-------------|----------|------|
| [payments-service](https://github.com/anurag-saran/payments-service) | ![Out-of-Cycle](https://img.shields.io/badge/Out--of--Cycle-c2410c?style=flat-square) | 5 CVEs |
| [fraud-service](https://github.com/anurag-saran/fraud-service) | ![Scheduled](https://img.shields.io/badge/Scheduled-a16207?style=flat-square) | 1 CVE |

## [payments-service](https://github.com/anurag-saran/payments-service) ![Out-of-Cycle](https://img.shields.io/badge/Out--of--Cycle-c2410c?style=flat-square)

Patch before the next feature release.

[Open pull request](https://github.com/anurag-saran/payments-service/pulls?q=is%3Apr+is%3Aopen+label%3Alightwell)

<details>
<summary>5 CVEs · libraries</summary>

| Library | Now → Lightwell | CVEs | Decision |
|---------|-----------------|------|----------|
| json | 20220320 → 20220320.0.0.rhlw-00003 | [`CVE-2022-45688`](https://access.redhat.com/security/cve/CVE-2022-45688) (7.5 HIGH)<br>[`CVE-2023-5072`](https://access.redhat.com/security/cve/CVE-2023-5072) (7.5 HIGH) | ![Out-of-Cycle](https://img.shields.io/badge/Out--of--Cycle-c2410c?style=flat-square) |
| json-path | 2.7.0 → 2.7.0.rhlw-00001 | [`CVE-2023-51074`](https://access.redhat.com/security/cve/CVE-2023-51074) (5.3 MEDIUM) | ![Out-of-Cycle](https://img.shields.io/badge/Out--of--Cycle-c2410c?style=flat-square) |
| woodstox-core | 6.0.3 → 6.0.3.rhlw-00001 | [`CVE-2022-40152`](https://access.redhat.com/security/cve/CVE-2022-40152) (6.5 MEDIUM) | ![Scheduled](https://img.shields.io/badge/Scheduled-a16207?style=flat-square) |
| spring-core | 5.3.18 → 5.3.18.rhlw-00010 | [`CVE-2025-41249`](https://access.redhat.com/security/cve/CVE-2025-41249) (7.5 HIGH) | ![Scheduled](https://img.shields.io/badge/Scheduled-a16207?style=flat-square) |

Updates with no CVE: commons-io 2.11.0 → 2.11.0.rhlw-00001, httpclient 4.5.12 → 4.5.12.rhlw-00001, jackson-databind 2.13.4 → 2.13.4.rhlw-00001, snakeyaml 1.30 → 1.33.0.rhlw-00001.

</details>

## [fraud-service](https://github.com/anurag-saran/fraud-service) ![Scheduled](https://img.shields.io/badge/Scheduled-a16207?style=flat-square)

Take it in the next release.

[Open pull request](https://github.com/anurag-saran/fraud-service/pulls?q=is%3Apr+is%3Aopen+label%3Alightwell)

<details>
<summary>1 CVE · libraries</summary>

| Library | Now → Lightwell | CVEs | Decision |
|---------|-----------------|------|----------|
| woodstox-core | 6.0.3 → 6.0.3.rhlw-00001 | [`CVE-2022-40152`](https://access.redhat.com/security/cve/CVE-2022-40152) (6.5 MEDIUM) | ![Scheduled](https://img.shields.io/badge/Scheduled-a16207?style=flat-square) |

Updates with no CVE: commons-fileupload 1.4.0 → 1.4.0.rhlw-00001, logback-classic 1.2.11 → 1.2.11.rhlw-00001.

</details>
