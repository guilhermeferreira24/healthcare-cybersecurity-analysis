SELECT
  Weakness,
  COUNT(*) AS total,
  ROUND(AVG(CVSS_Score), 2) AS avg_cvss
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
WHERE Weakness NOT IN ('NVD-CWE-noinfo', 'NVD-CWE-Other')
GROUP BY Weakness
ORDER BY total DESC
LIMIT 10;
