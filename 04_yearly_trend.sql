SELECT
  EXTRACT(YEAR FROM Published) AS year,
  COUNT(*) AS total_cves,
  COUNTIF(Severity IN ('HIGH','CRITICAL')) AS high_critical,
  ROUND(AVG(CVSS_Score), 2) AS avg_score
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
GROUP BY year
ORDER BY year;
