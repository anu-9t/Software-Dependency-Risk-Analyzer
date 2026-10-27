-- Software Dependency Risk & Vulnerability Impact Analyzer
-- DBMS Mini Project (Level 3), Section B
-- Anupam Tiwari (PES2UG24CS073), Ayushman Dey (PES2UG24CS102)

-- Part 1 is the DDL (report section 5), part 2 is the DML (report section 6).
-- Needs MySQL 8.0.16 or newer.
-- In 6.7 and 6.8 the statements that fail on purpose are commented out, so the whole file runs through.

-- drop the database first if it already exists, so the script can be run again
DROP DATABASE IF EXISTS dependency_analyzer;

-- PART 1: DDL (report section 5)

-- 5.1 Database and tables
CREATE DATABASE dependency_analyzer;
USE dependency_analyzer;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('ADMIN','ANALYST') NOT NULL DEFAULT 'ANALYST'
);

CREATE TABLE vendors (
    vendor_id INT AUTO_INCREMENT PRIMARY KEY,
    vendor_name VARCHAR(100) NOT NULL UNIQUE,
    country VARCHAR(50)
);

CREATE TABLE packages (
    package_id INT AUTO_INCREMENT PRIMARY KEY,
    package_name VARCHAR(100) NOT NULL,
    ecosystem ENUM('npm','PyPI','Maven') NOT NULL,
    vendor_id INT NOT NULL,
    UNIQUE (package_name, ecosystem),
    FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
);

CREATE TABLE package_versions (
    version_id INT AUTO_INCREMENT PRIMARY KEY,
    package_id INT NOT NULL,
    version_no VARCHAR(20) NOT NULL,
    release_date DATE NOT NULL,
    UNIQUE (package_id, version_no),
    FOREIGN KEY (package_id) REFERENCES packages(package_id)
        ON DELETE CASCADE
);

CREATE TABLE applications (
    app_id INT AUTO_INCREMENT PRIMARY KEY,
    app_name VARCHAR(100) NOT NULL UNIQUE,
    environment ENUM('PRODUCTION','INTERNAL','STAGING') NOT NULL,
    owner_team VARCHAR(100) NOT NULL
);

CREATE TABLE app_dependencies (
    app_id INT NOT NULL,
    version_id INT NOT NULL,
    PRIMARY KEY (app_id, version_id),
    FOREIGN KEY (app_id) REFERENCES applications(app_id)
        ON DELETE CASCADE,
    FOREIGN KEY (version_id) REFERENCES package_versions(version_id)
        ON DELETE CASCADE
);

CREATE TABLE package_dependencies (
    version_id INT NOT NULL,
    depends_on_version_id INT NOT NULL,
    PRIMARY KEY (version_id, depends_on_version_id),
    CHECK (version_id <> depends_on_version_id),
    FOREIGN KEY (version_id) REFERENCES package_versions(version_id)
        ON DELETE CASCADE,
    FOREIGN KEY (depends_on_version_id) REFERENCES package_versions(version_id)
        ON DELETE CASCADE
);

CREATE TABLE vulnerabilities (
    vuln_id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    title VARCHAR(200) NOT NULL,
    severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    cvss_score DECIMAL(3,1) NOT NULL CHECK (cvss_score BETWEEN 0 AND 10),
    published_date DATE NOT NULL
);

CREATE TABLE vulnerability_affects (
    vuln_id INT NOT NULL,
    version_id INT NOT NULL,
    fixed_in_version_id INT NULL,
    PRIMARY KEY (vuln_id, version_id),
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id)
        ON DELETE CASCADE,
    FOREIGN KEY (version_id) REFERENCES package_versions(version_id)
        ON DELETE CASCADE,
    FOREIGN KEY (fixed_in_version_id) REFERENCES package_versions(version_id)
        ON DELETE SET NULL
);

CREATE TABLE impact_reports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    vuln_id INT NOT NULL,
    run_by INT NOT NULL,
    run_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    apps_affected INT NOT NULL,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id),
    FOREIGN KEY (run_by) REFERENCES users(user_id)
);

-- 5.2 Indexes
CREATE INDEX idx_pkgdep_reverse
ON package_dependencies (depends_on_version_id);

CREATE INDEX idx_appdep_version
ON app_dependencies (version_id);

CREATE INDEX idx_vulnaff_version
ON vulnerability_affects (version_id);

CREATE INDEX idx_vuln_severity
ON vulnerabilities (severity);

-- 5.3 Views
CREATE VIEW v_vulnerable_versions AS
SELECT
    v.cve_id,
    v.severity,
    p.package_name,
    pv.version_no,
    CONCAT(fp.package_name, ' ', fv.version_no) AS fixed_in
FROM vulnerabilities v
JOIN vulnerability_affects va
    ON va.vuln_id = v.vuln_id
JOIN package_versions pv
    ON pv.version_id = va.version_id
JOIN packages p
    ON p.package_id = pv.package_id
LEFT JOIN package_versions fv
    ON fv.version_id = va.fixed_in_version_id
LEFT JOIN packages fp
    ON fp.package_id = fv.package_id;

CREATE VIEW v_app_footprint AS
SELECT
    a.app_name,
    a.environment,
    COUNT(ad.version_id) AS direct_dependencies
FROM applications a
LEFT JOIN app_dependencies ad
    ON ad.app_id = a.app_id
GROUP BY a.app_id, a.app_name, a.environment;

-- 5.4 Triggers
DELIMITER //
CREATE TRIGGER trg_pkgdep_before_insert
BEFORE INSERT ON package_dependencies
FOR EACH ROW
BEGIN
    IF EXISTS (
        SELECT 1
        FROM package_dependencies
        WHERE version_id = NEW.depends_on_version_id
          AND depends_on_version_id = NEW.version_id
    ) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Circular dependency detected';
    END IF;
END//
DELIMITER ;

DELIMITER //
CREATE TRIGGER trg_vulnaff_before_insert
BEFORE INSERT ON vulnerability_affects
FOR EACH ROW
BEGIN
    IF NEW.fixed_in_version_id IS NOT NULL
       AND (SELECT package_id FROM package_versions
            WHERE version_id = NEW.fixed_in_version_id)
        <> (SELECT package_id FROM package_versions
            WHERE version_id = NEW.version_id) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Fixed version must belong to the same package';
    END IF;
END//
DELIMITER ;

-- 5.5 Stored procedure and function
DELIMITER //
CREATE PROCEDURE sp_impact_analysis(
    IN p_cve VARCHAR(20),
    IN p_user_id INT
)
BEGIN
    DECLARE v_id INT;
    DECLARE v_count INT;
    SELECT vuln_id
    INTO v_id
    FROM vulnerabilities
    WHERE cve_id = p_cve;
    IF v_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Unknown CVE id';
    END IF;
    DROP TEMPORARY TABLE IF EXISTS tmp_affected_apps;
    CREATE TEMPORARY TABLE tmp_affected_apps (
        app_id INT PRIMARY KEY
    );
    INSERT INTO tmp_affected_apps
    WITH RECURSIVE affected (version_id) AS (
        SELECT va.version_id
        FROM vulnerability_affects va
        WHERE va.vuln_id = v_id
        UNION
        SELECT pd.version_id
        FROM package_dependencies pd
        JOIN affected a
            ON pd.depends_on_version_id = a.version_id
    )
    SELECT DISTINCT ad.app_id
    FROM app_dependencies ad
    WHERE ad.version_id IN (
        SELECT version_id
        FROM affected
    );
    SELECT COUNT(*)
    INTO v_count
    FROM tmp_affected_apps;
    INSERT INTO impact_reports (vuln_id, run_by, apps_affected)
    VALUES (v_id, p_user_id, v_count);
    SELECT
        a.app_name,
        a.environment,
        a.owner_team
    FROM applications a
    JOIN tmp_affected_apps t
        ON t.app_id = a.app_id
    ORDER BY FIELD(
        a.environment,
        'PRODUCTION',
        'INTERNAL',
        'STAGING'
    ), a.app_name;
END//
DELIMITER ;

DELIMITER //
CREATE FUNCTION fn_risk_level(
    p_cvss DECIMAL(3,1)
)
RETURNS VARCHAR(10)
DETERMINISTIC
BEGIN
    IF p_cvss >= 9.0 THEN
        RETURN 'CRITICAL';
    ELSEIF p_cvss >= 7.0 THEN
        RETURN 'HIGH';
    ELSEIF p_cvss >= 4.0 THEN
        RETURN 'MEDIUM';
    ELSE
        RETURN 'LOW';
    END IF;
END//
DELIMITER ;

-- 5.6 Verification, ALTER and DROP
-- (1) tables and views created
SHOW FULL TABLES;

-- (2) to (5) in the report only run DESC and information_schema queries to show the
-- structure, indexes, trigger and procedure. They change nothing, so they are not repeated here.

-- (6) ALTER and DROP
ALTER TABLE vendors
ADD COLUMN website VARCHAR(100);

DESC vendors;

ALTER TABLE vendors
DROP COLUMN website;

CREATE TABLE scratch_test (
    id INT PRIMARY KEY
);

DROP TABLE scratch_test;

DROP INDEX idx_vuln_severity
ON vulnerabilities;

CREATE INDEX idx_vuln_severity
ON vulnerabilities (severity);

SHOW TABLES LIKE 'scratch%';

-- PART 2: DML (report section 6)

-- 6.1 INSERT: users and vendors
INSERT INTO users (username, password_hash, role) VALUES
    ('admin1', '$2b$10$zrE5Uh.84sDAOvH2DJpC0uxsEhtjgd1NQ9ImdIlPdxlVJ1AFlHGyu', 'ADMIN'),
    ('analyst1', '$2b$10$gnzUWV9EMaGXupPnmPXYd.mRH8wF.8Q16yrnAUjNvv33ldXDeggEa', 'ANALYST');

INSERT INTO vendors (vendor_name, country) VALUES
    ('OpenForge', 'USA'),
    ('NimbleSoft', 'India'),
    ('CoreLabs', 'Germany');

SELECT * FROM users;

SELECT * FROM vendors;

-- 6.2 INSERT: packages and package versions
INSERT INTO packages (package_name, ecosystem, vendor_id) VALUES
    ('logcore', 'Maven', 1),
    ('jsonparse', 'npm', 1),
    ('httpkit', 'npm', 2),
    ('authlib', 'PyPI', 2),
    ('webframe', 'npm', 2),
    ('dbdriver', 'Maven', 3),
    ('cryptolite', 'PyPI', 3),
    ('uikit', 'npm', 1);

INSERT INTO package_versions
    (package_id, version_no, release_date)
VALUES
    (1, '1.0.0', '2024-01-10'),
    (1, '1.2.0', '2026-03-02'),
    (2, '2.0.0', '2024-05-20'),
    (2, '2.1.0', '2026-04-11'),
    (3, '3.4.0', '2024-09-01'),
    (3, '3.5.0', '2026-04-20'),
    (4, '1.0.0', '2024-11-15'),
    (5, '4.0.0', '2024-10-05'),
    (5, '4.1.0', '2026-05-01'),
    (6, '5.2.0', '2024-08-08'),
    (7, '0.9.0', '2023-12-12'),
    (8, '1.0.0', '2025-02-14');

SELECT
    pv.version_id,
    p.package_name,
    pv.version_no,
    pv.release_date
FROM package_versions pv
JOIN packages p
    ON p.package_id = pv.package_id
ORDER BY p.package_name, pv.version_no;

-- 6.3 INSERT: applications and their direct dependencies
INSERT INTO applications (app_name, environment, owner_team) VALUES
    ('PaymentService', 'PRODUCTION', 'Payments'),
    ('UserPortal', 'PRODUCTION', 'Web'),
    ('AdminConsole', 'INTERNAL', 'Operations'),
    ('ReportingTool', 'STAGING', 'Analytics'),
    ('MobileAPI', 'PRODUCTION', 'Mobile');

INSERT INTO app_dependencies (app_id, version_id) VALUES
    (1, 8),
    (1, 10),
    (2, 9),
    (2, 12),
    (3, 7),
    (4, 10),
    (5, 7),
    (5, 9);

SELECT
    a.app_name,
    p.package_name,
    pv.version_no
FROM app_dependencies ad
JOIN applications a
    ON a.app_id = ad.app_id
JOIN package_versions pv
    ON pv.version_id = ad.version_id
JOIN packages p
    ON p.package_id = pv.package_id
ORDER BY a.app_name, p.package_name;

-- 6.4 INSERT: package-to-package dependencies (each pair is version_id, depends_on_version_id)
INSERT INTO package_dependencies
    (version_id, depends_on_version_id)
VALUES
    (5, 1),
    (5, 3),
    (6, 2),
    (7, 5),
    (7, 11),
    (8, 5),
    (9, 6),
    (10, 1),
    (12, 4);

SELECT COUNT(*) AS dependency_edges
FROM package_dependencies;

-- 6.5 INSERT: vulnerabilities and affected versions
INSERT INTO vulnerabilities
    (cve_id, title, severity, cvss_score, published_date)
VALUES
    ('CVE-2026-1001', 'Remote code execution in logcore', 'CRITICAL', 9.8, '2026-06-15'),
    ('CVE-2026-2002', 'Denial of service in jsonparse', 'HIGH', 7.5, '2026-07-02'),
    ('CVE-2025-3003', 'Weak key derivation in cryptolite', 'MEDIUM', 5.3, '2025-11-20');

INSERT INTO vulnerability_affects
    (vuln_id, version_id, fixed_in_version_id)
VALUES
    (1, 1, 2),
    (2, 3, 4),
    (3, 11, NULL);

-- 6.6 TRANSACTION (COMMIT): register a new httpkit version with its dependencies
START TRANSACTION;

INSERT INTO package_versions
    (package_id, version_no, release_date)
VALUES
    (3, '3.6.0', '2026-08-15');

INSERT INTO package_dependencies
    (version_id, depends_on_version_id)
VALUES
    (LAST_INSERT_ID(), 2),
    (LAST_INSERT_ID(), 4);

COMMIT;

SELECT
    pv.version_id,
    p.package_name,
    pv.version_no,
    pd.depends_on_version_id
FROM package_versions pv
JOIN packages p
    ON p.package_id = pv.package_id
JOIN package_dependencies pd
    ON pd.version_id = pv.version_id
WHERE pv.version_no = '3.6.0';

-- 6.7 TRANSACTION (ROLLBACK): a failed dependency insert undoes the whole registration
START TRANSACTION;

INSERT INTO package_versions
    (package_id, version_no, release_date)
VALUES
    (6, '5.3.0', '2026-09-01');

-- This insert fails on purpose (version 999 does not exist, ERROR 1452), so it is commented
-- out to let the script run through. Remove the -- signs to see the error in the client.
-- INSERT INTO package_dependencies
--     (version_id, depends_on_version_id)
-- VALUES
--     (LAST_INSERT_ID(), 999);

ROLLBACK;

SELECT COUNT(*) AS dbdriver_530_rows
FROM package_versions
WHERE package_id = 6
  AND version_no = '5.3.0';

-- 6.8 TRIGGERS: a two-way circular dependency and a fix in the wrong package are rejected
-- Version 6 already depends on version 2, so this reverse link is blocked by the trigger
-- (ERROR 1644, circular dependency detected). Commented out so the script runs through;
-- remove the -- signs to try it.
-- INSERT INTO package_dependencies
--     (version_id, depends_on_version_id)
-- VALUES
--     (2, 6);

-- The second trigger checks that the fixed version belongs to the same package as the
-- affected version. Version 5 is httpkit 3.4.0 but version 2 is logcore 1.2.0, so this row
-- is blocked (ERROR 1644, fixed version must belong to the same package). Commented out
-- for the same reason as above. The rows inserted in 6.5 are valid and pass the trigger.
-- INSERT INTO vulnerability_affects
--     (vuln_id, version_id, fixed_in_version_id)
-- VALUES
--     (1, 5, 2);

-- 6.9 UPDATE: change the owner team of an application
UPDATE applications
SET owner_team = 'Data Platform'
WHERE app_name = 'ReportingTool';

SELECT
    app_name,
    environment,
    owner_team
FROM applications;

-- 6.10 DELETE: decommission an application (dependencies removed by ON DELETE CASCADE)
INSERT INTO applications
    (app_name, environment, owner_team)
VALUES
    ('LegacyBilling', 'INTERNAL', 'Finance');

INSERT INTO app_dependencies (app_id, version_id)
SELECT app_id, 1
FROM applications
WHERE app_name = 'LegacyBilling';

SELECT COUNT(*) AS rows_before
FROM app_dependencies
WHERE app_id = (
    SELECT app_id
    FROM applications
    WHERE app_name = 'LegacyBilling'
);

DELETE FROM applications
WHERE app_name = 'LegacyBilling';

SELECT COUNT(*) AS rows_after
FROM app_dependencies
WHERE app_id = 6;

-- 6.11 SELECT (JOIN): remediation list - vulnerable versions and the version that fixes them
SELECT
    v.cve_id,
    v.severity,
    p.package_name,
    pv.version_no AS vulnerable_version,
    CONCAT(fp.package_name, ' ', fv.version_no) AS upgrade_to
FROM vulnerability_affects va
JOIN vulnerabilities v
    ON v.vuln_id = va.vuln_id
JOIN package_versions pv
    ON pv.version_id = va.version_id
JOIN packages p
    ON p.package_id = pv.package_id
LEFT JOIN package_versions fv
    ON fv.version_id = va.fixed_in_version_id
LEFT JOIN packages fp
    ON fp.package_id = fv.package_id
ORDER BY v.cvss_score DESC;

-- 6.12 SELECT (GROUP BY, HAVING): most depended-on package versions
SELECT
    p.package_name,
    pv.version_no,
    COUNT(*) AS direct_dependents
FROM package_dependencies pd
JOIN package_versions pv
    ON pv.version_id = pd.depends_on_version_id
JOIN packages p
    ON p.package_id = pv.package_id
GROUP BY
    pv.version_id,
    p.package_name,
    pv.version_no
HAVING COUNT(*) >= 2
ORDER BY direct_dependents DESC;

-- 6.13 SELECT (LEFT JOIN, aggregate): dependency footprint of each application
SELECT
    a.app_name,
    a.environment,
    COUNT(ad.version_id) AS direct_dependencies
FROM applications a
LEFT JOIN app_dependencies ad
    ON ad.app_id = a.app_id
GROUP BY
    a.app_id,
    a.app_name,
    a.environment
ORDER BY direct_dependencies DESC, a.app_name;

-- 6.14 SELECT (multi-table JOIN, aggregate): vendors ranked by number of vulnerable versions
SELECT
    vd.vendor_name,
    COUNT(DISTINCT pv.version_id) AS vulnerable_versions
FROM vendors vd
JOIN packages p
    ON p.vendor_id = vd.vendor_id
JOIN package_versions pv
    ON pv.package_id = p.package_id
JOIN vulnerability_affects va
    ON va.version_id = pv.version_id
GROUP BY
    vd.vendor_id,
    vd.vendor_name
ORDER BY vulnerable_versions DESC;

-- 6.15 SELECT (subqueries): packages with no vulnerable version, and versions with above-average dependents
SELECT package_name
FROM packages p
WHERE NOT EXISTS (
    SELECT 1
    FROM package_versions pv
    JOIN vulnerability_affects va
        ON va.version_id = pv.version_id
    WHERE pv.package_id = p.package_id
);

SELECT
    depends_on_version_id,
    COUNT(*) AS dependents
FROM package_dependencies
GROUP BY depends_on_version_id
HAVING COUNT(*) > (
    SELECT AVG(c)
    FROM (
        SELECT COUNT(*) AS c
        FROM package_dependencies
        GROUP BY depends_on_version_id
    ) t
);

-- 6.16 SELECT (recursive CTE): every package version on a dependency chain from logcore 1.0.0
WITH RECURSIVE dependents AS (
    SELECT
        pv.version_id,
        0 AS depth,
        CAST(
            CONCAT(p.package_name, ' ', pv.version_no)
            AS CHAR(255)
        ) AS path
    FROM package_versions pv
    JOIN packages p
        ON p.package_id = pv.package_id
    WHERE pv.version_id = 1
    UNION ALL
    SELECT
        pd.version_id,
        d.depth + 1,
        CONCAT(
            p2.package_name,
            ' ',
            pv2.version_no,
            ' -> ',
            d.path
        )
    FROM dependents d
    JOIN package_dependencies pd
        ON pd.depends_on_version_id = d.version_id
    JOIN package_versions pv2
        ON pv2.version_id = pd.version_id
    JOIN packages p2
        ON p2.package_id = pv2.package_id
    WHERE d.depth < 10
)
SELECT depth, path
FROM dependents
ORDER BY depth, path;

-- 6.17 Views: querying v_vulnerable_versions and v_app_footprint
SELECT * FROM v_vulnerable_versions;

SELECT * FROM v_app_footprint;

-- 6.18 STORED PROCEDURE: blast radius of CVE-2026-1001
CALL sp_impact_analysis('CVE-2026-1001', 1);

-- 6.19 STORED PROCEDURE: blast radius of CVE-2026-2002, then the saved reports
CALL sp_impact_analysis('CVE-2026-2002', 2);

SELECT
    r.report_id,
    v.cve_id,
    u.username AS run_by,
    r.apps_affected
FROM impact_reports r
JOIN vulnerabilities v
    ON v.vuln_id = r.vuln_id
JOIN users u
    ON u.user_id = r.run_by;

-- 6.20 FUNCTION: risk level calculated from the CVSS score, next to the stored severity
SELECT
    cve_id,
    cvss_score,
    severity,
    fn_risk_level(cvss_score) AS computed_level
FROM vulnerabilities
ORDER BY cvss_score DESC;
