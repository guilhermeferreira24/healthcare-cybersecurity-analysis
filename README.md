# Healthcare Cybersecurity Vulnerabilities Analysis

## Overview

This project analyzes 1,497 real CVE (Common Vulnerabilities and Exposures) 
records from hospitals, medical devices, EHR systems and other healthcare 
infrastructure. The goal was to identify risk patterns, attack vectors, and 
vulnerability trends across the healthcare sector using SQL and Power BI.

The dataset contains real CVE records sourced from Kaggle, covering the period 
from 2000 to 2025.

---

## Objective

- Identify the most vulnerable healthcare categories and attack patterns
- Analyze severity distribution and CVSS score trends over time
- Surface the most common weakness types (CWE) across the sector
- Measure how long vulnerabilities remain unpatched
- Build an interactive Power BI dashboard for stakeholder reporting

---

## Dataset

| Field | Detail |
|-------|--------|
| Source | [Kaggle — Healthcare Cybersecurity Vulnerabilities](link) |
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
| `Attack_Vector` | STRING | NETWORK / LOCAL / PHYSICAL / ADJACENT |
| `Weakness` | STRING | CWE weakness code |

---

## Tools & Stack

- **Python (Pandas)** — Data cleaning and preparation
- **Google BigQuery** — SQL analysis (CTEs, Window Functions, RANK)
- **Power BI** — 4-page interactive dashboard
- **GitHub** — Version control and portfolio

---

## Approach

The project was divided into three stages:

**Stage 1 — Data Cleaning (Python)**
Load and inspect the raw CSV, handle NULL values, standardize date formats 
and remove incomplete records before loading into BigQuery.

**Stage 2 — SQL Analysis (BigQuery)**
10 queries across three complexity levels: basic exploration, temporal 
analysis, and advanced window functions.

**Stage 3 — Power BI Dashboard**
4-page interactive dashboard built on top of the BigQuery data, 
connected via native Power BI → BigQuery connector.

---

## Stage 1 — Data Cleaning (Python)

```python
import pandas as pd

df = pd.read_csv('healthcare_cybersecurity_10k.csv')

# Initial inspection
print(df.shape)
print(df.dtypes)
print(df.isnull().sum())
```

### Null values found

| Column | Nulls |
|--------|-------|
| Severity | 18 |
| Attack_Vector | 63 |
| CVSS_Score | 63 |
| Weakness | 0 |

```python
# Remove rows with nulls in critical columns
df_clean = df.dropna(subset=['Severity', 'Attack_Vector', 'CVSS_Score'])

# Standardize date columns
df_clean['Published'] = pd.to_datetime(df_clean['Published'])
df_clean['Last_Modified'] = pd.to_datetime(df_clean['Last_Modified'])

# Calculate days unpatched
df_clean['Days_Since_Update'] = (
    df_clean['Last_Modified'] - df_clean['Published']
).dt.days

print(f"Clean dataset: {df_clean.shape} records")
# Output: Clean dataset: 1,497 records
```

---

## Stage 2 — SQL Analysis (BigQuery)

### Basic Exploration

**Query 1 — Severity Distribution**

```sql
SELECT
  Severity,
  COUNT(*) AS total_cves,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS pct
FROM `project.dataset.healthcare_cves`
GROUP BY Severity
ORDER BY total_cves DESC;
```

**Results**

| Severity | Total CVEs | % |
|----------|-----------|---|
| MEDIUM | 720 | 48.10% |
| HIGH | 492 | 32.87% |
| CRITICAL | 151 | 10.09% |
| LOW | 134 | 8.95% |

**Query 2 — Top 10 Weakness Types (CWE)**

```sql
SELECT
  Weakness,
  COUNT(*) AS total,
  ROUND(AVG(CVSS_Score), 2) AS avg_cvss
FROM `project.dataset.healthcare_cves`
WHERE Weakness NOT IN ('NVD-CWE-noinfo', 'NVD-CWE-Other')
GROUP BY Weakness
ORDER BY total DESC
LIMIT 10;
```

**Results**

| Weakness | Total | Avg CVSS |
|----------|-------|----------|
| CWE-89 (SQL Injection) | 312 | 7.82 |
| CWE-79 (XSS) | 198 | 6.14 |
| CWE-74 | 127 | 7.01 |
| CWE-200 | 89 | 6.45 |
| CWE-255 | 67 | 7.23 |

**Query 3 — CVEs by Healthcare Category**

```sql
SELECT
  Keyword,
  COUNT(*) AS total_cves,
  ROUND(AVG(CVSS_Score), 2) AS avg_cvss,
  COUNTIF(Severity = 'CRITICAL') AS critical_count
FROM `project.dataset.healthcare_cves`
GROUP BY Keyword
ORDER BY total_cves DESC;
```

**Results**

| Keyword | Total CVEs | Avg CVSS | Critical |
|---------|-----------|----------|---------|
| hospital | 460 | 6.71 | 53 |
| patient | 253 | 6.55 | 18 |
| OpenEMR | 113 | 7.12 | 22 |
| DICOM | 103 | 6.89 | 8 |
| pharmacy | 92 | 6.34 | 5 |
