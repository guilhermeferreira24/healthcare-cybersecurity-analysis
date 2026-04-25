WITH yearly AS (
  SELECT
    EXTRACT(YEAR FROM Published) AS year,
    ROUND(AVG(CVSS_Score), 2) AS avg_cvss
  FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
  GROUP BY year
)
SELECT
  year,
  avg_cvss,
  ROUND(AVG(avg_cvss) OVER (
    ORDER BY year
    ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
  ), 2) AS moving_avg_3yr
FROM yearly
ORDER BY year;
