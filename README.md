# Healthcare Cybersecurity Vulnerabilities Analysis

## Overview

This project analyzes real CVE (Common Vulnerabilities and Exposures) records from hospitals, medical devices, EHR systems and other healthcare infrastructure. The goal was to identify risk patterns, attack vectors, and vulnerability trends across the healthcare sector using Python, SQL (BigQuery) and Power BI.

The dataset contains real CVE records sourced from Kaggle, covering the period from 2000 to 2025.

***

## Objective

- Identify the most vulnerable healthcare categories and attack patterns
- Analyze severity distribution and CVSS score trends over time
- Surface the most common weakness types (CWE) across the sector
- Measure how long vulnerabilities remain unpatched
- Build an interactive 4-page Power BI dashboard for stakeholder reporting

***

## Dataset

| Field | Detail |
|-------|--------|
| Source | [Kaggle — Healthcare Cybersecurity Vulnerabilities](https://www.kaggle.com) |
| Records | 1,497 CVEs (after cleaning) |
| Period | 2000–2025 |
| Domain | Hospitals, Medical Devices, EHR, Pharmacy, ICU, Blood Bank |

### Schema

| Column | Type | Description |
|--------|------|-------------|
| `CVE_ID` | STRING | Unique CVE identifier |
| `Keyword` | STRING | Healthcare category (hospital, patient, EHR…) |
| `Published` | DATE | CVE publication date |
| `Last_Modified` | DATE | Date of last update |
| `Status` | STRING | CVE status (Modified, Deferred…) |
| `Severity` | STRING | LOW / MEDIUM / HIGH / CRITICAL |
| `CVSS_Score` | FLOAT | Risk score from 0 to 10 |
| `Attack_Vector` | STRING | NETWORK / LOCAL / PHYSICAL / ADJACENT_NETWORK |
| `Weakness` | STRING | CWE weakness code |

***

## Tools & Stack

- **Python (Pandas)** — Data cleaning and preparation (Google Colab)
- **Google BigQuery** — SQL analysis (CTEs, Window Functions, RANK, PERCENTILE)
- **Power BI** — 4-page interactive dashboard with DAX measures
- **GitHub** — Version control and portfolio

***

## Approach

The project was divided into three stages:

**Stage 1 — Data Cleaning (Python/Google Colab)**
Load and inspect the raw CSV, fix encoding issues in the Description column, and export a clean version for BigQuery ingestion.

**Stage 2 — SQL Analysis (BigQuery)**
10 queries across three complexity levels: basic exploration, temporal analysis, and advanced window functions.

**Stage 3 — Power BI Dashboard**
4-page interactive dashboard built on top of the BigQuery data, connected via the native Power BI → BigQuery connector.

***

## Stage 1 — Data Cleaning (Python)

```python
from google.colab import files
import pandas as pd
import io

# Upload file
uploaded = files.upload()

# Load CSV
df = pd.read_csv(io.BytesIO(list(uploaded.values())[0]), on_bad_lines='skip')
print(df.shape)
print(df.columns.tolist())

# Fix encoding issues in Description column
df['Description'] = df['Description'].astype(str).str.replace('\n', ' ', regex=False)
df['Description'] = df['Description'].str.replace('\r', ' ', regex=False)
df['Description'] = df['Description'].str.replace('"', "'", regex=False)

# Export clean file
df.to_csv('healthcare_clean.csv', index=False, quoting=1)
files.download('healthcare_clean.csv')
print("✅ Clean file exported!")
```

The raw dataset contained special characters and line breaks inside the `Description` column that would break CSV parsing on BigQuery ingestion. The cleaning step standardized these values before upload.

***

## Stage 2 — SQL Analysis (BigQuery)

All queries were run on Google BigQuery Sandbox (free tier) against the table `healthcare-cybersecurity.healthcare_cves.cve_records`.

### Basic Exploration

**Query 1 — Severity Distribution**

```sql
SELECT
  Severity,
  COUNT(*) AS total_cves,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS pct
FROM healthcare-cybersecurity.healthcare_cves.cve_records
GROUP BY Severity
ORDER BY total_cves DESC;
```

| Severity | Total CVEs | % |
|----------|-----------|---|
| MEDIUM | 720 | 48.10% |
| HIGH | 492 | 32.87% |
| CRITICAL | 151 | 10.09% |
| LOW | 134 | 8.95% |

***

**Query 2 — CVEs by Healthcare Category**

```sql
SELECT
  Keyword,
  COUNT(*) AS total_cves,
  ROUND(AVG(CVSS_Score), 2) AS avg_cvss,
  COUNTIF(Severity = 'HIGH') AS high_count,
  COUNTIF(Severity = 'CRITICAL') AS critical_count
FROM healthcare-cybersecurity.healthcare_cves.cve_records
GROUP BY Keyword
ORDER BY total_cves DESC;
```

| Keyword | Total CVEs | Avg CVSS | High | Critical |
|---------|-----------|----------|------|---------|
| hospital | 460 | 6.71 | 126 | 53 |
| patient | 253 | 6.55 | 89 | 18 |
| OpenEMR | 113 | 7.12 | 67 | 22 |
| DICOM | 103 | 6.89 | 67 | 8 |
| pharmacy | 92 | 6.34 | 34 | 5 |

***

**Query 3 — Top 10 Weakness Types (CWE)**

```sql
SELECT
  Weakness,
  COUNT(*) AS total,
  ROUND(AVG(CVSS_Score), 2) AS avg_cvss
FROM healthcare-cybersecurity.healthcare_cves.cve_records
WHERE Weakness NOT IN ('NVD-CWE-noinfo', 'NVD-CWE-Other')
GROUP BY Weakness
ORDER BY total DESC
LIMIT 10;
```

| Weakness | Total | Avg CVSS |
|----------|-------|----------|
| CWE-89 (SQL Injection) | 312 | 7.82 |
| CWE-79 (XSS) | 198 | 6.14 |
| CWE-74 | 127 | 7.01 |
| CWE-200 | 89 | 6.45 |
| CWE-255 | 67 | 7.23 |

***

### Temporal Analysis

**Query 4 — Annual CVE Trend**

```sql
SELECT
  EXTRACT(YEAR FROM Published) AS year,
  COUNT(*) AS total_cves,
  COUNTIF(Severity IN ('HIGH','CRITICAL')) AS high_critical,
  ROUND(AVG(CVSS_Score), 2) AS avg_score
FROM healthcare-cybersecurity.healthcare_cves.cve_records
GROUP BY year
ORDER BY year;
```

| Year | Total CVEs | High + Critical | Avg Score |
|------|-----------|-----------------|-----------|
| 2015 | 28 | 14 | 6.21 |
| 2018 | 89 | 42 | 6.78 |
| 2021 | 163 | 78 | 6.55 |
| 2024 | 268 | 134 | 6.61 |
| 2025 | 112 | 58 | 6.49 |

***

**Query 5 — Attack Vector vs Severity**

```sql
SELECT
  Attack_Vector,
  COUNTIF(Severity = 'LOW') AS low,
  COUNTIF(Severity = 'MEDIUM') AS medium,
  COUNTIF(Severity = 'HIGH') AS high,
  COUNTIF(Severity = 'CRITICAL') AS critical,
  COUNT(*) AS total
FROM healthcare-cybersecurity.healthcare_cves.cve_records
GROUP BY Attack_Vector
ORDER BY total DESC;
```

| Attack Vector | Low | Medium | High | Critical | Total |
|---------------|-----|--------|------|---------|-------|
| NETWORK | 116 | 622 | 420 | 120 | 1,278 |
| LOCAL | 14 | 76 | 52 | 24 | 166 |
| ADJACENT_NETWORK | 3 | 14 | 12 | 5 | 34 |
| PHYSICAL | 1 | 8 | 8 | 2 | 19 |

***

**Query 6 — High Risk CVEs Unpatched the Longest**

```sql
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
FROM healthcare-cybersecurity.healthcare_cves.cve_records
WHERE
  Severity IN ('HIGH', 'CRITICAL')
  AND CVSS_Score >= 9.0
ORDER BY days_since_update DESC
LIMIT 20;
```

Returns the 20 most dangerous CVEs (score ≥ 9.0) that have gone the longest without being updated — a direct measure of unaddressed critical risk in the sector.

***

### Advanced — Window Functions & CTEs

**Query 7 — Dominant Severity per Healthcare Category (DENSE_RANK)**

The challenge here was finding the most common severity *per keyword*, not globally. A simple `GROUP BY + ORDER BY` would only return a global ranking. The solution used two chained CTEs + `DENSE_RANK()`:

```sql
WITH severity_counts AS (
  SELECT
    Keyword,
    Severity,
    COUNT(*) AS cnt
  FROM healthcare-cybersecurity.healthcare_cves.cve_records
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
```

`DENSE_RANK()` was used instead of `RANK()` to avoid gaps in ranking when ties exist — ensuring every keyword always has a rank 1 result.

***

**Query 8 — 3-Year Moving Average of CVSS Score**

```sql
WITH yearly AS (
  SELECT
    EXTRACT(YEAR FROM Published) AS year,
    ROUND(AVG(CVSS_Score), 2) AS avg_cvss
  FROM healthcare-cybersecurity.healthcare_cves.cve_records
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
```

The `ROWS BETWEEN 2 PRECEDING AND CURRENT ROW` frame creates a rolling 3-year window that smooths out annual spikes and reveals the true long-term severity trend.

***

**Query 9 — CVSS Percentile Rank per Keyword**

```sql
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
FROM healthcare-cybersecurity.healthcare_cves.cve_records
ORDER BY Keyword, CVSS_Score DESC;
```

`PERCENTILE_CONT` calculates the median CVSS score within each keyword group — a more robust central tendency measure than the mean, since CVSS scores are not normally distributed.

***

**Query 10 — Average Days to Update per Category**

```sql
SELECT
  Keyword,
  ROUND(AVG(DATE_DIFF(Last_Modified, Published, DAY)), 0) AS avg_days_to_update,
  MIN(DATE_DIFF(Last_Modified, Published, DAY)) AS min_days,
  MAX(DATE_DIFF(Last_Modified, Published, DAY)) AS max_days,
  COUNT(*) AS total
FROM healthcare-cybersecurity.healthcare_cves.cve_records
GROUP BY Keyword
ORDER BY avg_days_to_update DESC;
```

| Keyword | Avg Days | Min | Max |
|---------|----------|-----|-----|
| insulin pump | 612 | 14 | 2,847 |
| pacemaker | 589 | 7 | 3,102 |
| hospital | 360 | 1 | 4,215 |
| EHR | 298 | 3 | 1,876 |
| pharmacy | 241 | 2 | 1,543 |

***

## Stage 3 — Power BI Dashboard

Connected Power BI Desktop to BigQuery via the native **Get Data → Google BigQuery** connector (Import mode).

### DAX Measures

```dax
Total CVEs = COUNTROWS(cve_records)

Avg CVSS Score = AVERAGE(cve_records[CVSS_Score])

Critical & High % =
DIVIDE(
    COUNTROWS(FILTER(cve_records, cve_records[Severity] IN {"HIGH", "CRITICAL"})),
    COUNTROWS(cve_records)
)

Avg Days Unpatched =
AVERAGEX(
    cve_records,
    DATEDIFF(cve_records[Published], cve_records[Last_Modified], DAY)
)

Network Attack % =
DIVIDE(
    COUNTROWS(FILTER(cve_records, cve_records[Attack_Vector] = "NETWORK")),
    COUNTROWS(cve_records)
)
```

### Dashboard Pages

**Page 1 — Overview**

![image alt](https://github.com/guilhermeferreira24/healthcare-cybersecurity-analysis/blob/271cd349c7b3f7f160f4a64946f1bcb77b1727a5/overview.png.png)

Key visuals: Gauge (Avg CVSS), KPI cards, CVEs by Severity (donut), CVEs by Keyword (bar), CVEs by Year (area chart)

***

**Page 2 — Risk Analysis**

![image alt](https://github.com/guilhermeferreira24/healthcare-cybersecurity-analysis/blob/a32191513eeaa793003c32623bed3c8ac25d7c22/risk_analysis.png.png)

Key visuals: Top 10 CWE Weaknesses, Avg CVSS by Keyword, Scatter (CVSS vs Days Unpatched), Matrix (Keyword × Severity)

***

**Page 3 — Attack Vectors**

![image alt](https://github.com/guilhermeferreira24/healthcare-cybersecurity-analysis/blob/1ac50a1fa4ee1af37f223fcb2bcbb994c22f41ae/attack_vectors.png.png)

Key visuals: Treemap (Attack Vector × Keyword), Stacked Bar (Attack Vector by Year), Donut (Attack Vector distribution), KPI card (Network Attack %)

***

**Page 4 — Timeline**

![image alt](https://github.com/guilhermeferreira24/healthcare-cybersecurity-analysis/blob/1ac50a1fa4ee1af37f223fcb2bcbb994c22f41ae/timeline.png.png)

Key visuals: Line chart (CVEs by Year × Severity), Column chart (Avg CVSS by Year), KPI card (Peak Year CVEs)

***

## Key Findings

-  **85% of attacks are NETWORK-based** — remote exploitation dominates the healthcare sector across all categories and years
-  **Hospitals account for 31% of all CVEs** (460 out of 1,497) — nearly double the second most targeted category
-  **43% of CVEs are HIGH or CRITICAL severity** — a significant proportion of vulnerabilities pose immediate risk
-  **CWE-89 (SQL Injection) is the #1 weakness** — basic injection attacks remain unresolved in healthcare systems
-  **Average 360 days to patch** — vulnerabilities in the sector go unaddressed for nearly a full year on average
-  **CVE volume exploded post-2015** — driven by the digitalization of health records and connected medical devices
-  **Insulin pumps and pacemakers take longest to patch** (600+ days avg) — likely due to FDA approval requirements for firmware updates

***

## What I Learned

- **`DENSE_RANK()` vs `RANK()`** — `DENSE_RANK()` never skips rank numbers on ties, making it the safer choice for top-N filtering per partition
- **Chained CTEs** — each CTE builds on the previous one; first aggregate, then rank, then filter. Trying to filter in the same step as ranking causes errors
- **`ROWS BETWEEN x PRECEDING AND CURRENT ROW`** — defines the window frame for rolling aggregations; without it, window functions use the full partition by default
- **`PERCENTILE_CONT` in BigQuery** — unlike most aggregate functions, percentile functions in BigQuery require a window clause even when computing a single value per partition
- **`DATE_DIFF` vs `DATEDIFF`** — BigQuery uses `DATE_DIFF(end, start, DAY)` with the unit as the third argument, unlike SQL Server's `DATEDIFF(DAY, start, end)`
- **Power BI DAX vs SQL** — DAX measures are recalculated dynamically based on filter context; the same measure returns different values depending on which slicer is active
- **BigQuery Sandbox** — fully functional free tier (1TB/month queries, 10GB storage) with no credit card required; sufficient for any portfolio project

***

## Source

Dataset: [Kaggle — Healthcare Cybersecurity Vulnerabilities](https://www.kaggle.com)  
SQL Environment: Google BigQuery Sandbox  
BI Tool: Microsoft Power BI Desktop
