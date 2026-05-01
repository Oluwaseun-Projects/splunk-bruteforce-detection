# 🔐 Brute Force Detection in Splunk (Windows + Linux)

## 📌 Project Overview

This project demonstrates how to detect brute force login attempts using Splunk across both Linux and Windows systems.

It covers:

* Log ingestion (Linux & Windows)
* Attack simulation using Hydra
* Detection using SPL
* Alert creation
* Dashboard visualization

---
## 🧪 Attack Simulation (Kali Linux)

Brute force attacks were simulated using **Hydra** from a Kali Linux machine.

### SSH Attack (Linux Target)

```bash
hydra -l kayode -P /usr/share/wordlists/rockyou.txt -t 5 ssh://192.168.200.30
```

### RDP Attack (Windows Target)

```bash
hydra -l seun -P /usr/share/wordlists/rockyou.txt -t 5 rdp://192.168.200.20
```

---

## 📥 Data Sources

| Source  | Description                                   |
| ------- | --------------------------------------------- |
| Linux   | `/var/log/auth.log`                           |
| Windows | Security Logs (EventCode 4625 - Failed Login) |

---

## 🔍 Log Verification

Ensure both logs are being ingested:

```spl
index=* ("Failed password" OR "4625")
| stats count by sourcetype
```

---

## 🧠 Detection Logic

Brute force is identified as:

* Multiple failed login attempts
* From the same IP or targeting the same user
* Threshold: ≥ 5 attempts

---

## 💻 SPL Detection Query

```spl
index=* ("Failed password" OR "4625")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "for (invalid user )?(?<user>\w+)"
| eval user=coalesce(Account_Name, user)
| eval src_ip=coalesce(Source_Network_Address, src_ip)
| stats count by src_ip, user
| where count >= 5
| sort - count
```

---

## 🚨 Alert Configuration

* **Name:** Brute Force Login Detection
* **Type:** Scheduled
* **Frequency:** Every 5 minutes
* **Trigger Condition:** Number of Results > 5
* **Action:** Email notification

---

## 📊 Dashboard (Brute Force Monitoring)

### Panels:

1. **Top Attacking IPs**
2. **Targeted Users**
3. **Activity Over Time**

---

## 📸 Screenshots

### 🔹 Attack Simulation (Kali Linux)

<img width="1609" height="884" alt="Kali attack on Linux and Windows" src="https://github.com/user-attachments/assets/26aaf6b9-4157-4ac7-8d62-0ccf829f2ae7" />


### 🔹 Linux Failed Password Logs

![Linux Logs](screenshots/linux-failed.png)

### 🔹 Windows Failed Logins

![Windows Logs](screenshots/windows-failed.png)

### 🔹 Combined Detection Results

![Detection](screenshots/detection-results.png)

### 🔹 Alert Configuration

![Alert](screenshots/alert-config.png)

### 🔹 Dashboard View

![Dashboard](screenshots/dashboard.png)

---

## 🔎 Key Findings

* IP `192.168.201.100` generated the highest number of failed login attempts
* Multiple users were targeted including:

  * `kayode`
  * `seun`
* Attack patterns clearly indicate brute force behavior

---

## ⚠️ Limitations

* Linux logs required regex extraction (`rex`)
* No field normalization (CIM not implemented)
* Detection based on threshold (no behavioral analytics)

---

## 🚀 Future Improvements

* Implement **CIM (Common Information Model)**
* Use **field aliases and props.conf**
* Add **correlation rules**
* Improve detection using **time-based thresholds**

---

## 🎯 Conclusion

This project demonstrates a practical approach to detecting brute force attacks using Splunk across heterogeneous systems. It highlights core SOC skills including log analysis, SPL usage, alerting, and dashboard creation.

---

## 👤 Author

**Seun**
Cybersecurity / SOC Analyst

---
