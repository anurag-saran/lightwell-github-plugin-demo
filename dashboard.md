# App priority

Each row is one application. Priority is the Remediation Priority Engine result for that app, the same outcome the remediation pull request shows. Libraries are the Lightwell updates available now. CVEs are the ones those updates address.

| App | Priority | Available libraries | CVEs addressed |
|-----|----------|---------------------|----------------|
| [payments-service](https://github.com/anurag-saran/payments-service) | ![Out-of-Cycle](https://img.shields.io/badge/Out--of--Cycle-c2410c?style=flat-square) | json 20220320 → 20220320.0.0.rhlw-00003<br>json-path 2.7.0 → 2.7.0.rhlw-00001<br>woodstox-core 6.0.3 → 6.0.3.rhlw-00001<br>spring-core 5.3.18 → 5.3.18.rhlw-00010<br>commons-io 2.11.0 → 2.11.0.rhlw-00001<br>httpclient 4.5.12 → 4.5.12.rhlw-00001<br>jackson-databind 2.13.4 → 2.13.4.rhlw-00001<br>snakeyaml 1.30 → 1.33.0.rhlw-00001 | [`CVE-2022-45688`](https://access.redhat.com/security/cve/CVE-2022-45688) (7.5 HIGH)<br>[`CVE-2023-5072`](https://access.redhat.com/security/cve/CVE-2023-5072) (7.5 HIGH)<br>[`CVE-2023-51074`](https://access.redhat.com/security/cve/CVE-2023-51074) (5.3 MEDIUM)<br>[`CVE-2022-40152`](https://access.redhat.com/security/cve/CVE-2022-40152) (6.5 MEDIUM)<br>[`CVE-2025-41249`](https://access.redhat.com/security/cve/CVE-2025-41249) (7.5 HIGH) |
| [fraud-service](https://github.com/anurag-saran/fraud-service) | — | commons-fileupload 1.4.0 → 1.4.0.rhlw-00001<br>logback-classic 1.2.11 → 1.2.11.rhlw-00001 | — |
