WITH severity_counts AS (
  SELECT
    Keyword,
    Severity,
    COUNT(*) AS cnt
  FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
  GROUP BY Keyword, Severity
),
severity_ranked AS (
  SELECT
    Keyword,
    Severity,
    cnt,
    DENSE_RANK() OVER (
      PARTITION BY Keyword
      ORDER BY cnt DESC
    ) AS rank
  FROM severity_counts
)
SELECT * FROM severity_ranked
WHERE rank = 1
ORDER BY cnt DESC;
