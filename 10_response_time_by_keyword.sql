SELECT
  Keyword,
  ROUND(AVG(DATE_DIFF(Last_Modified, Published, DAY)), 0) AS avg_days_to_update,
  MIN(DATE_DIFF(Last_Modified, Published, DAY)) AS min_days,
  MAX(DATE_DIFF(Last_Modified, Published, DAY)) AS max_days,
  COUNT(*) AS total
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
GROUP BY Keyword
ORDER BY avg_days_to_update DESC;
