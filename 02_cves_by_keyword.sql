SELECT
  Keyword,
  COUNT(*) AS total_cves,
  ROUND(AVG(CVSS_Score), 2) AS avg_cvss,
  COUNTIF(Severity = 'HIGH') AS high_count,
  COUNTIF(Severity = 'CRITICAL') AS critical_count
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
GROUP BY Keyword
ORDER BY total_cves DESC;
