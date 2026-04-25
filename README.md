# 🏥 Healthcare Cybersecurity Vulnerabilities Analysis

![Power BI](https://img.shields.io/badge/Power%20BI-F2C811?style=for-the-badge&logo=powerbi&logoColor=black)
![BigQuery](https://img.shields.io/badge/BigQuery-4285F4?style=for-the-badge&logo=googlecloud&logoColor=white)
![SQL](https://img.shields.io/badge/SQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)

## Overview
Analysis of **1,497 real CVE records** from hospitals, medical devices and EHR systems,
sourced from Kaggle. This project explores vulnerability patterns, attack vectors, 
severity trends and patch response times across the healthcare sector using 
SQL (Google BigQuery) and Power BI.

---

## Dashboard Preview

### Overview
![Overview](screenshots/overview.png)

### Risk Analysis
![Risk Analysis](screenshots/risk_analysis.png)

### Attack Vectors
![Attack Vectors](screenshots/attack_vectors.png)

### Timeline
![Timeline](screenshots/timeline.png)

---

## Dataset
| Field | Detail |
|-------|--------|
| Source | [Kaggle — Healthcare Cybersecurity Vulnerabilities](YOUR_KAGGLE_LINK) |
| Records | 1,497 CVEs |
| Period | 2000–2025 |
| Fields | CVE_ID, Keyword, Severity, CVSS_Score, Attack_Vector, Weakness, Published, Last_Modified |

---

## Key Findings
- 🌐 **85% of attacks occur via NETWORK vector** — remote exploitability dominates healthcare
- 🔴 **43% of CVEs are HIGH or CRITICAL severity** — nearly half carry serious risk
- 🏥 **Hospitals are the most targeted category** with 460 CVEs — almost double the next category
- ⏱️ **Average 360 days to patch vulnerabilities** — critical systems left exposed for nearly a year
- 💉 **CWE-89 (SQL Injection) is the #1 weakness** — basic input validation still failing in 2025
- 📈 **CVE volume exploded post-2015** — growing attack surface as healthcare digitizes

---

## Tools & Stack
| Tool | Purpose |
|------|---------|
| **Google BigQuery** | Cloud data warehouse, SQL analysis |
| **Power BI** | 4-page interactive dashboard |
| **Power Query** | Data cleaning & transformation |
| **DAX** | Custom measures and KPIs |
| **Kaggle** | Dataset source |

---

## Database Schema
| Column | Type | Description |
|--------|------|-------------|
| `CVE_ID` | STRING | Unique vulnerability identifier |
| `Keyword` | STRING | Healthcare category (hospital, EHR, medical device…) |
| `Severity` | STRING | LOW / MEDIUM / HIGH / CRITICAL |
| `CVSS_Score` | FLOAT | Risk score 0–10 |
| `Attack_Vector` | STRING | NETWORK / LOCAL / PHYSICAL / ADJACENT_NETWORK |
| `Weakness` | STRING | CWE code (e.g. CWE-89) |
| `Published` | DATE | CVE publication date |
| `Last_Modified` | DATE | Last update date |

---

## SQL Analysis
Queries are organised by complexity in the `/queries` folder:

| File | Description |
|------|-------------|
| [`01_basic_exploration.sql`](queries/01_basic_exploration.sql) | Severity distribution, CVEs by keyword, top weaknesses |
| [`02_temporal_analysis.sql`](queries/02_temporal_analysis.sql) | CVE trends by year, avg days to patch, attack vector evolution |
| [`03_advanced_window_functions.sql`](queries/03_advanced_window_functions.sql) | DENSE_RANK by keyword, PERCENTILE, 3-year moving average |

---

## Dashboard Pages
| Page | Key Visuals |
|------|-------------|
| **Overview** | Gauge (Avg CVSS), KPI cards, CVEs by severity & keyword, trend line |
| **Risk Analysis** | Top 10 CWE weaknesses, CVSS by keyword, scatter plot, severity matrix |
| **Attack Vectors** | Treemap, stacked bar by year, donut, Network Attack % KPI |
| **Timeline** | CVEs by year & severity, Avg CVSS evolution 2000–2025 |

---

## DAX Measures
```dax
-- Average CVSS Score
Avg CVSS Score = AVERAGE(cve_records[CVSS_Score])

-- Critical & High percentage
Critical & High % = 
DIVIDE(
    COUNTROWS(FILTER(cve_records, cve_records[Severity] IN {"HIGH","CRITICAL"})),
    COUNTROWS(cve_records)
)

-- Average days unpatched
Avg Days Unpatched = 
AVERAGEX(
    cve_records,
    DATEDIFF(cve_records[Published], cve_records[Last_Modified], DAY)
)

-- Network attack percentage
Network Attack % = 
DIVIDE(
    COUNTROWS(FILTER(cve_records, cve_records[Attack_Vector] = "NETWORK")),
    COUNTROWS(cve_records)
)
```

---

## What I Learned
- **BigQuery Sandbox** — free cloud SQL environment with 1TB/month of free queries
- **DAX vs columns** — calculated columns create circular dependencies; 
  always use measures for aggregations
- **Power Query for data cleaning** — filtering NULLs upstream keeps the 
  model clean and avoids incorrect totals
- **Sort by Column** — custom ordering of categorical fields (CRITICAL → HIGH → 
  MEDIUM → LOW) requires a helper numeric column
- **Monocromatic design** — one colour family with varying intensity looks 
  more professional than multiple unrelated colours
- **Window functions in BigQuery** — `DENSE_RANK()`, `PERCENTILE_CONT()` and 
  moving averages work identically to PostgreSQL syntax

---

## Source
Dataset sourced from [Kaggle](YOUR_KAGGLE_LINK) — Real CVE records from 
hospital, medical device & EHR vulnerability disclosures.
