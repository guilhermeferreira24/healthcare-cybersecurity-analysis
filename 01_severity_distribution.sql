SELECT
  Severity,
  COUNT(*) AS total_cves,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS pct
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
GROUP BY Severity
ORDER BY total_cves DESC;


| Severity | Total CVEs | % |
|----------|-----------|---|
| MEDIUM | 720 | 48.10% |
| HIGH | 492 | 32.87% |
| CRITICAL | 151 | 10.09% |
| LOW | 134 | 8.95% |
