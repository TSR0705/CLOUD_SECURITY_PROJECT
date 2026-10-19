# Phase P22: Service Privilege Separation & Least-Privilege IAM Matrix

## 1. Overview and Trust Zone Topology

In accordance with **ADR-0004**, **ADR-0003**, and **DEC-003**, Phase P22 enforces strict least privilege across relational database roles, cloud object storage identities, and container network boundaries. Monolithic credentials and administrative privileges have been completely eliminated from all pipeline services.

## 2. Service-to-Identity Mapping

| Service Name                              | PostgreSQL Database Role | Storage IAM Access Key ID                    | Storage Secret Source                           | Docker Compose Networks   |
| :---------------------------------------- | :----------------------- | :------------------------------------------- | :---------------------------------------------- | :------------------------ |
| **Edge API (`sug-api`)**                  | `sug_api`                | `sug-api-key`                                | `/run/secrets/aws_secret_access_key_api`        | `edge`, `data`, `store`   |
| **Scanner Worker (`sug-scanner`)**        | `sug_scanner`            | `sug-scanner-key`                            | `/run/secrets/aws_secret_access_key_scanner`    | `data`, `store`, `scan`   |
| **Promotion Worker (`sug-promoter`)**     | `sug_promoter`           | `sug-promoter-key`                           | `/run/secrets/aws_secret_access_key_promoter`   | `data`, `store`           |
| **Replication Worker (`sug-replicator`)** | `sug_replicator`         | `sug-replicator-key`                         | `/run/secrets/aws_secret_access_key_replicator` | `data`, `store`, `egress` |
| **Security Auditor / Dashboard**          | `sug_auditor`            | N/A (Auditor uses signed token verification) | N/A                                             | `edge`, `data`            |
| **Database Migrations / Schema Admin**    | `sug_admin`              | Administrative credentials                   | `/run/secrets/db_password`                      | `data`                    |

---

## 3. PostgreSQL Database Role Permission Matrix

| Database Entity                 | `sug_api`                             | `sug_scanner`                     | `sug_promoter`                  | `sug_replicator`                          | `sug_auditor`                         | `sug_admin` |
| :------------------------------ | :------------------------------------ | :-------------------------------- | :------------------------------ | :---------------------------------------- | :------------------------------------ | :---------- |
| **`upload_sessions`**           | `SELECT`, `INSERT`, `UPDATE`          | `SELECT`                          | `SELECT`                        | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`files`**                     | `SELECT`, `INSERT`, `UPDATE`          | ❌ None                           | `SELECT`, `UPDATE (status)`     | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`file_versions`**             | `SELECT`, `INSERT`                    | `SELECT`                          | `SELECT`                        | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`cloud_objects`**             | `SELECT`                              | ❌ None                           | `SELECT`, `INSERT` (Clean zone) | `SELECT`, `INSERT` (Replica zone via RLS) | `SELECT`                              | `ALL`       |
| **`scan_jobs`**                 | `SELECT`, `INSERT`                    | `SELECT`, `UPDATE` (lease/status) | ❌ None                         | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`scan_results`**              | `SELECT`                              | `SELECT`, `INSERT` (Immutable)    | `SELECT`                        | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`security_decisions`**        | `SELECT`                              | ❌ None                           | `SELECT`, `INSERT`              | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`promotion_jobs`**            | ❌ None                               | ❌ None                           | `SELECT`, `INSERT`, `UPDATE`    | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`replication_jobs`**          | ❌ None                               | ❌ None                           | `INSERT`                        | `SELECT`, `UPDATE`                        | `SELECT`                              | `ALL`       |
| **`audit_events`**              | `SELECT`                              | ❌ Direct table access            | ❌ Direct table access          | `SELECT`                                  | `SELECT`                              | `ALL`       |
| **`audit_checkpoints`**         | `SELECT`                              | ❌ None                           | ❌ None                         | ❌ None (Revoked in 014)                  | `SELECT`                              | `ALL`       |
| **`users`**                     | `SELECT`, `UPDATE` (lockout/login)    | ❌ None                           | ❌ None                         | ❌ None                                   | `SELECT` (non-sensitive columns only) | `ALL`       |
| **`api_keys`**                  | `SELECT`                              | ❌ None                           | ❌ None                         | ❌ None                                   | `SELECT` (non-sensitive columns only) | `ALL`       |
| **`refresh_tokens`**            | `SELECT`, `INSERT`, `UPDATE`          | ❌ None                           | ❌ None                         | ❌ None                                   | ❌ None                               | `ALL`       |
| **`applications`**              | `SELECT`, `UPDATE (active_policy_id)` | ❌ None                           | ❌ None                         | ❌ None                                   | `SELECT`                              | `ALL`       |
| **`audit_append()`**            | `EXECUTE`                             | `EXECUTE`                         | `EXECUTE`                       | `EXECUTE`                                 | ❌ None                               | `EXECUTE`   |
| **`audit_checkpoint_create()`** | `EXECUTE`                             | ❌ None                           | ❌ None                         | ❌ None                                   | ❌ None                               | `EXECUTE`   |

---

## 4. Cloud Object Storage Permission Matrix

| Bucket / Path                             | API Identity (`sug-api-key`)      | Scanner Identity (`sug-scanner-key`)  | Promoter Identity (`sug-promoter-key`)   | Replicator Identity (`sug-replicator-key`)        |
| :---------------------------------------- | :-------------------------------- | :------------------------------------ | :--------------------------------------- | :------------------------------------------------ |
| **`sug-quarantine-local` (`incoming/*`)** | `s3:PutObject` (streaming upload) | `s3:GetObject`, `s3:GetObjectVersion` | `s3:GetObjectVersion` (source read)      | ❌ Denied                                         |
| **`sug-clean-local` (`clean/*`)**         | ❌ Denied                         | ❌ Denied                             | `s3:PutObject` (exact version promotion) | `s3:GetObjectVersion` (replica source read)       |
| **`sug-replica-local` (GCS)**             | ❌ Denied                         | ❌ Denied                             | ❌ Denied                                | `storage.objects.create` (`ifGenerationMatch: 0`) |
| **`sug-audit-local` (`checkpoints/*`)**   | `s3:PutObject`, `s3:GetObject`    | ❌ Denied                             | ❌ Denied                                | ❌ Denied                                         |

---

## 5. Blast-Radius Analysis (Mitigation for Risk R-10)

If the scanner container is subjected to Remote Code Execution (RCE) via a malicious payload or untrusted file parser:

1. **Zero Clean Object Writes**: The scanner possesses neither database write grants to `cloud_objects` nor S3 write access to `sug-clean-local`.
2. **Zero Decision Forgery**: The database strictly rejects `INSERT INTO security_decisions` from `sug_scanner` with `permission denied`.
3. **Zero Autonomous Promotion**: The scanner cannot insert into `promotion_jobs` or modify `files.status`.
4. **Zero Audit Tampering**: The scanner cannot modify `audit_events`, mutate `scan_results` (enforced by trigger `scan_results_immutable` and absence of UPDATE grant), or insert `audit_checkpoints`.
5. **Zero Data Exfiltration Egress**: The scanner container runs on an internal network (`internal: true`) with dropped default routes; direct IP and DNS external connections fail immediately with `ENETUNREACH` / `EAI_AGAIN`.
