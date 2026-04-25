SELECT
  Severity,
  COUNT(*) AS total_cves,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS pct
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
GROUP BY Severity
ORDER BY total_cves DESC;

