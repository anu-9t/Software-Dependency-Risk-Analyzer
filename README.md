# Software Dependency Risk & Vulnerability Impact Analyzer

DBMS Mini Project (Level 3), Section B, PES University, Team 27

- Anupam Tiwari (PES2UG24CS073)
- Ayushman Dey (PES2UG24CS102)

## About the project

Software is built from packages, and packages depend on other packages. When a
vulnerability (CVE) is found in one package, checking who uses it directly is not
enough. An application may be exposed through a chain, for example
`app -> webframe -> httpkit -> logcore`, where logcore is the vulnerable package.

This project answers: **if this CVE is real, which applications are affected,
directly or through the chain, and which version fixes it?**

MySQL is the authoritative database and holds all records. A stored procedure
follows the dependency chain with a recursive query and lists every affected
application, and each run is saved as an impact report. Neo4j (graph database)
will be added later for graph queries and is not part of this submission.

Terms: a **CVE** is the public id of a vulnerability, the **CVSS score** is its
severity from 0 to 10, a **direct dependency** is a package the app lists itself,
a **transitive dependency** is one reached through other packages.

## Repository contents

| Path | What it is |
| --- | --- |
| `sql/dependency_analyzer.sql` | Complete DDL and DML: tables, indexes, views, triggers, procedure, function, sample data and queries |
| `docs/DBMS_Project_Report.pdf` | Full project report |

## Database design

10 tables. Each ER entity is a table, and each many-to-many relationship has its
own link table.

| Table | Meaning | Key columns |
| --- | --- | --- |
| `vendors` | Company that publishes packages | vendor_id, vendor_name, country |
| `packages` | A library, e.g. logcore | package_id, package_name, vendor_id |
| `package_versions` | One release, e.g. logcore 1.0.0 | version_id, package_id, version_no, release_date |
| `package_dependencies` | A version depends on another version (the dependency graph) | version_id, depends_on_version_id |
| `applications` | A product that uses packages | app_id, app_name, environment, owner_team |
| `app_dependencies` | Which package versions an application uses | app_id, version_id |
| `vulnerabilities` | A CVE with its CVSS score | vuln_id, cve_id, cvss_score, severity |
| `vulnerability_affects` | Which versions a CVE affects, and the version that fixes it | vuln_id, version_id, fixed_in_version_id |
| `users` | Administrator or Security Analyst | user_id, username, role |
| `impact_reports` | Saved result of one analysis | report_id, vuln_id, run_by, apps_affected |

`version_id` is the auto-generated primary key of `package_versions`. It identifies
one release, whereas `version_no` is only its label such as `1.2.0`.

## How to run

Requires MySQL 8.0.16 or newer (CHECK constraints and recursive queries). Tested on 8.0.46.

1. Open the MySQL client:

   ```
   mysql -u root -p
   ```

2. Run the script. It drops and recreates the `dependency_analyzer` database, so it
   can be run again safely:

   ```
   source sql/dependency_analyzer.sql
   ```

   Use the full path to the file if the client was not started in the repository folder.

3. Select the database:

   ```
   USE dependency_analyzer;
   ```

The script runs without errors. The statements that fail on purpose (shown in the
failure demos below) are commented out in the file.

Expected row counts after a full run: users 2, vendors 3, packages 8,
package_versions 13, package_dependencies 11, applications 5, app_dependencies 8,
vulnerabilities 3, vulnerability_affects 3, impact_reports 2.

Tip: paste the statements below from this page one at a time, or save them in a
text file and use `source`. Copying from a PDF can split names at underscores.

## Advanced features and demonstrations

### 1. Indexes

An index is a sorted lookup structure on a column. It lets MySQL jump to matching
rows instead of scanning the whole table. It speeds up SELECT, JOIN and WHERE, and
costs a little on INSERT and UPDATE.

```sql
CREATE INDEX index_name ON table_name (column_name);
```

| Index | On | What it speeds up |
| --- | --- | --- |
| `idx_pkgdep_reverse` | package_dependencies(depends_on_version_id) | "Who depends on this version?", asked at every step of the impact analysis |
| `idx_appdep_version` | app_dependencies(version_id) | Finding the applications that use a version |
| `idx_vulnaff_version` | vulnerability_affects(version_id) | Finding the vulnerabilities that affect a version |
| `idx_vuln_severity` | vulnerabilities(severity) | Filtering CVEs by severity |

Demo, listing all 4 indexes (one per table):

```sql
SELECT index_name, table_name, column_name FROM information_schema.statistics WHERE table_schema = 'dependency_analyzer' AND index_name LIKE 'idx\_%';
```

`SHOW INDEX FROM package_dependencies;` shows 3 rows for that one table: the
composite primary key (2 rows, one per column) and `idx_pkgdep_reverse`.

### 2. Views

A view is a saved SELECT that behaves like a virtual table. It stores no data and
runs its query each time it is used, which hides complicated joins behind one name.

```sql
CREATE VIEW view_name AS SELECT ... FROM ... JOIN ...;
```

| View | What it shows |
| --- | --- |
| `v_vulnerable_versions` | Each CVE with its severity, the vulnerable package and version, and the version that fixes it (NULL if no fix exists yet) |
| `v_app_footprint` | Each application with its environment and the number of direct dependencies |

Demo:

```sql
SELECT * FROM v_vulnerable_versions;
SELECT * FROM v_app_footprint;
```

Expected: 3 CVEs (CRITICAL logcore 1.0.0, HIGH jsonparse 2.0.0, MEDIUM cryptolite 0.9.0
with no fix) and 5 applications.

### 3. Transactions

A transaction groups statements into one all-or-nothing unit. `COMMIT` makes the
changes permanent, `ROLLBACK` undoes everything since `START TRANSACTION`.

```sql
START TRANSACTION;
-- statements
COMMIT;      -- or ROLLBACK;
```

Demo 1, COMMIT: register a new httpkit release together with its two dependencies.
(3.6.0 already exists after the main script, so 3.7.0 is used here.)

```sql
START TRANSACTION;
INSERT INTO package_versions (package_id, version_no, release_date) VALUES (3, '3.7.0', '2026-10-01');
INSERT INTO package_dependencies (version_id, depends_on_version_id) VALUES (LAST_INSERT_ID(), 2), (LAST_INSERT_ID(), 4);
COMMIT;
```

`LAST_INSERT_ID()` is the `version_id` MySQL just generated for the new row.

Demo 2, ROLLBACK (the second insert fails, so the first one is undone too):

```sql
START TRANSACTION;
INSERT INTO package_versions (package_id, version_no, release_date) VALUES (6, '5.3.0', '2026-09-01');
INSERT INTO package_dependencies (version_id, depends_on_version_id) VALUES (LAST_INSERT_ID(), 999);
ROLLBACK;
SELECT COUNT(*) AS dbdriver_530_rows FROM package_versions WHERE package_id = 6 AND version_no = '5.3.0';
```

The second insert fails with `ERROR 1452` (foreign key, version 999 does not exist)
and the count is `0`.

### 4. Triggers

A trigger is code stored in the database that runs automatically on INSERT, UPDATE
or DELETE. Both triggers here are `BEFORE INSERT` checks that reject a bad row with
`SIGNAL SQLSTATE '45000'`. `NEW.column` is the value in the row being inserted.

```sql
DELIMITER //
CREATE TRIGGER trigger_name
BEFORE INSERT ON table_name
FOR EACH ROW
BEGIN
    IF <bad condition> THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'error message';
    END IF;
END//
DELIMITER ;
```

| Trigger | On | Rule |
| --- | --- | --- |
| `trg_pkgdep_before_insert` | package_dependencies | Blocks a two-way circular dependency |
| `trg_vulnaff_before_insert` | vulnerability_affects | The fixed version must belong to the same package as the vulnerable version |

Failure demo 1, circular dependency (version 6 already depends on version 2):

```sql
INSERT INTO package_dependencies (version_id, depends_on_version_id) VALUES (2, 6);
```

Result: `ERROR 1644 (45000): Circular dependency detected`

Failure demo 2, fix in a different package (version 5 is httpkit, version 2 is logcore):

```sql
INSERT INTO vulnerability_affects (vuln_id, version_id, fixed_in_version_id) VALUES (1, 5, 2);
```

Result: `ERROR 1644 (45000): Fixed version must belong to the same package`

### 5. Stored procedure

A procedure is a named block of SQL run with `CALL`. It can modify data and return
results.

```sql
DELIMITER //
CREATE PROCEDURE proc_name(IN p_param TYPE, ...)
BEGIN
    DECLARE v_var TYPE;
    -- statements
END//
DELIMITER ;

CALL proc_name(value1, value2);
```

`sp_impact_analysis(p_cve, p_user_id)` does the following:

1. Looks up the CVE and raises `Unknown CVE id` if it does not exist.
2. Creates a temporary table `tmp_affected_apps`.
3. Runs a recursive query (`WITH RECURSIVE`): it starts from the versions the CVE
   hits and repeatedly adds every version that depends on one already found.
4. Finds every application that uses any of those versions.
5. Saves one row in `impact_reports`.
6. Returns the affected applications, ordered PRODUCTION, INTERNAL, STAGING.

Demo:

```sql
CALL sp_impact_analysis('CVE-2026-1001', 1);
CALL sp_impact_analysis('CVE-2026-2002', 2);
SELECT * FROM impact_reports;
```

CVE-2026-1001 returns 4 applications (MobileAPI, PaymentService, AdminConsole,
ReportingTool) and CVE-2026-2002 returns 3. Each call adds one row to
`impact_reports`.

Failure demo, unknown CVE:

```sql
CALL sp_impact_analysis('CVE-0000-0000', 1);
```

Result: `ERROR 1644 (45000): Unknown CVE id`

### 6. Stored function

A function returns a single value and can be used inside a query like a built-in
function. `DETERMINISTIC` declares that the same input always gives the same output,
which MySQL requires when binary logging is on.

```sql
DELIMITER //
CREATE FUNCTION fn_name(p_param TYPE)
RETURNS return_type
DETERMINISTIC
BEGIN
    RETURN value;
END//
DELIMITER ;
```

`fn_risk_level(cvss_score)` returns CRITICAL for 9.0 and above, HIGH for 7.0 and
above, MEDIUM for 4.0 and above, otherwise LOW.

Demo:

```sql
SELECT cve_id, cvss_score, severity, fn_risk_level(cvss_score) AS computed_level FROM vulnerabilities ORDER BY cvss_score DESC;
```

Result: 9.8 CRITICAL, 7.5 HIGH, 5.3 MEDIUM, matching the stored severity.

Packages whose vulnerabilities the function classes as CRITICAL:

```sql
SELECT p.package_name, pv.version_no, v.cve_id, v.cvss_score, fn_risk_level(v.cvss_score) AS computed_level FROM vulnerabilities v JOIN vulnerability_affects va ON va.vuln_id = v.vuln_id JOIN package_versions pv ON pv.version_id = va.version_id JOIN packages p ON p.package_id = pv.package_id WHERE fn_risk_level(v.cvss_score) = 'CRITICAL';
```

Result: logcore 1.0.0, CVE-2026-1001, 9.8.

## Notes

- The demos that change data (the COMMIT transaction and the procedure calls) are
  meant to be run once per fresh database. Running the main script again resets
  everything.
- The three failure demos and the unknown-CVE call are expected to print errors,
  which shows the database enforcing its rules.
- `ERROR 1644 (45000)` is the custom error raised by `SIGNAL`.
