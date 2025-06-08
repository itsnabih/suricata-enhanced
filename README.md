# 📄 Suricata SQL Injection Detection Rules (With Flowbits)

This rule set is designed to detect a wide variety of **SQL Injection (SQLi)** attempts using Suricata IDS. It includes detection for classic SQL injection patterns, blind injection techniques, error-based injections, fingerprinting attempts, and even detection of automated tools like **SQLMap**.

Each rule includes `flowbits` logic to ensure that alerts are **triggered only once per flow**, reducing noise and false positives.

---

## 📚 Categories of Detection

### 🔹 1. Basic SQL Injection Patterns

* **Quote-based attacks** (e.g. `' or "` used in GET/POST parameters)
* **Comment markers** (e.g. `--`, `#`, `/*`) used to terminate legitimate queries

### 🔹 2. Boolean-based Blind SQL Injection

* Detects payloads like `AND 1=1`, `OR 2=2`, commonly used to bypass logic-based authentication checks.

### 🔹 3. Time-based Blind SQL Injection

* Detects time delays caused by:

  * `SLEEP(n)`
  * `pg_sleep(n)`
  * `WAITFOR DELAY 'n'`
* These are used to infer data via time delays in the response.

### 🔹 4. UNION-based Injection

* Detects UNION SELECT statements that are used to merge results from other tables.

### 🔹 5. Error-based Injection

* Monitors for functions such as:

  * `EXTRACTVALUE()`
  * `CONCAT(0x...)`
* Often used to cause SQL errors that leak database structure.

### 🔹 6. Encoded Payload Detection

* Detects use of encoded payloads including:

  * `%27` (URL-encoded `'`)
  * `%2D%2D` (`--`), `%23` (`#`), etc.

### 🔹 7. Fingerprinting Attempts

* Detects attempts to retrieve banner/version information using:

  * `@@version`, `version()`, `@@SERVERNAME`

### 🔹 8. ORDER BY Column Testing

* Detects brute force column count attempts using `ORDER BY <number>`.

### 🔹 9. NULL Byte Injection

* Detects `%00` null byte injections, often used to terminate input early or bypass filters.

### 🔹 10. Common Database Functions

* Detects access to:

  * User and session info (`CURRENT_USER()`, `USER()`, `SESSION_USER()`)
  * Database info (`DATABASE()`, `SCHEMA()`)

### 🔹 11. Hex Encoding Payloads

* Detects payloads containing hexadecimal-encoded SQL data (e.g., `0x61646d696e`).

### 🔹 12. File Read Attempts

* Detects use of `LOAD_FILE('/...')` to exfiltrate files from the database server.

### 🔹 13. SQLMap Tool Detection

* Flags known SQLMap User-Agent strings used by automated testing tools.

---

## ✅ Flowbits Logic

* `flowbits:isnotset,alerted`
  ➤ Prevents triggering the same rule multiple times in a session.
* `flowbits:set,alerted`
  ➤ Marks that an alert was already triggered for that session.

---

## 🛠 How to Use

1. Save the rules into a file, e.g., `sql_injection.rules`.
2. Include this rule file in your `suricata.yaml` under the `rule-files` section:

   ```yaml
   rule-files:
     - sql_injection.rules
   ```
3. Restart Suricata to apply the new rules:

   ```bash
   sudo systemctl restart suricata
   ```
4. Check `/var/log/suricata/fast.log` or `/var/log/suricata/eve.json` for alerts.

---

## 📎 Notes

* These rules focus on **HTTP-based SQL injection**. For database-layer traffic, additional rules for `mysql` or `pgsql` protocols may be needed.
* Make sure Suricata is running with **HTTP parsing enabled** (via `af-packet`, `pcap`, or `NFQUEUE` with `http` module enabled).

---

## 📌 Credits

Created and maintained for environments performing **web application penetration testing**, **threat hunting**, or **security monitoring** for SQL injection.

---
