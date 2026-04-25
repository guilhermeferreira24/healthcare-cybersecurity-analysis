SELECT
  CVE_ID,
  Keyword,
  CVSS_Score,
  ROUND(PERCENTILE_CONT(CVSS_Score, 0.5) OVER (
    PARTITION BY Keyword
  ), 2) AS median_cvss_by_keyword,
  ROUND(PERCENT_RANK() OVER (
    PARTITION BY Keyword
    ORDER BY CVSS_Score
  ) * 100, 1) AS percentile_rank
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
ORDER BY Keyword, CVSS_Score DESC;
