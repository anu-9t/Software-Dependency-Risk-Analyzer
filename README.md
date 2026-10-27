# Software Dependency Risk & Vulnerability Impact Analyzer

DBMS Mini Project (Level 3), Section B, PES University, Team 27

- Anupam Tiwari (PES2UG24CS073)
- Ayushman Dey (PES2UG24CS102)

## About

Applications depend on packages, and packages depend on other packages. When a
vulnerability (CVE) is found in one package, this project finds every package
version and application affected by it, directly or through the dependency chain,
and shows which version fixes it.

MySQL is the authoritative database. Neo4j (graph database) will be added later
for graph queries and is not part of this submission.

## Contents

| Path | What it is |
| --- | --- |
| `sql/dependency_analyzer.sql` | Complete DDL and DML: tables, indexes, views, triggers, procedure, function, sample data and queries |
| `docs/DBMS_Project_Report.pdf` | Full project report |

## Requirements

- MySQL 8.0.16 or newer (CHECK constraints and recursive queries are used)
- Tested on MySQL 8.0.46

## How to run

1. Start the MySQL client from the repository folder:

   ```
   mysql -u root -p
   ```

2. Run the main script. It drops and recreates the `dependency_analyzer`
   database, so it can be run again safely:

   ```
   source sql/dependency_analyzer.sql
   ```

   Or, without entering the client:

   ```
   mysql -u root -p < sql/dependency_analyzer.sql
   ```

3. Check the data:

   ```
   USE dependency_analyzer;
   SHOW TABLES;
   ```

   Expected row counts after a full run: users 2, vendors 3, packages 8,
   package_versions 13, package_dependencies 11, applications 5,
   app_dependencies 8, vulnerabilities 3, vulnerability_affects 3,
   impact_reports 2.

## Database design

10 tables: `users`, `vendors`, `packages`, `package_versions`,
`package_dependencies`, `applications`, `app_dependencies`, `vulnerabilities`,
`vulnerability_affects`, `impact_reports`.

## Advanced features

| Feature | Objects |
| --- | --- |
| Indexes | `idx_pkgdep_reverse`, `idx_appdep_version`, `idx_vulnaff_version`, `idx_vuln_severity` |
| Views | `v_vulnerable_versions`, `v_app_footprint` |
| Transactions | COMMIT and ROLLBACK examples (new release with dependencies; failed insert rolled back) |
| Triggers | `trg_pkgdep_before_insert` (blocks circular dependencies), `trg_vulnaff_before_insert` (fixed version must belong to the same package) |
| Stored procedure | `sp_impact_analysis(cve_id, user_id)` finds all affected applications using a recursive query and saves an impact report |
| Stored function | `fn_risk_level(cvss_score)` returns CRITICAL, HIGH, MEDIUM or LOW |

Example:

```sql
CALL sp_impact_analysis('CVE-2026-1001', 1);
SELECT cve_id, cvss_score, fn_risk_level(cvss_score) FROM vulnerabilities;
```
