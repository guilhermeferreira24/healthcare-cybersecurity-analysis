SELECT
  Attack_Vector,
  COUNTIF(Severity = 'LOW') AS low,
  COUNTIF(Severity = 'MEDIUM') AS medium,
  COUNTIF(Severity = 'HIGH') AS high,
  COUNTIF(Severity = 'CRITICAL') AS critical,
  COUNT(*) AS total
FROM `healthcare-cybersecurity.healthcare_cves.cve_records`
GROUP BY Attack_Vector
ORDER BY total DESC;
