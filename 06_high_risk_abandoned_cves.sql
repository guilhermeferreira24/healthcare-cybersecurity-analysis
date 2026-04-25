SELECT
  CVE_ID,
  Keyword,
  Severity,
  CVSS_Score,
  Published,
  Last_Modified,
  DATE_DIFF(
    CURRENT_DATE(),
    Last_Modified,
    DAY
  ) AS days_since_update
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
WHERE
  Severity IN ('HIGH', 'CRITICAL')
  AND CVSS_Score >= 9.0
ORDER BY days_since_update DESC
LIMIT 20;
