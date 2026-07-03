# SIEMTRIX

**A Modular SIEM-Based Monitoring Framework for Industrial Control Systems**

> Final Year Project — Dept. of Cyber Security, NCSA, Air University, Islamabad  
> Zain Rashid (221543) · Riaz Ahmed Ansari (221591)  
> Supervisor: Dr. Ammar Masood

---

## Overview

SIEMTRIX is an open-source ICS cybersecurity monitoring and detection platform built entirely from open-source components. It addresses a critical gap in the ICS security landscape — the absence of affordable, architecturally rigorous monitoring solutions accessible to SMEs, academic institutions, and research environments that cannot justify the cost of commercial platforms like Nozomi Networks or Dragos.

The system implements a defense-in-depth strategy across four security zones, enforces a pull-only command delivery mechanism that ensures OT devices are never directly reachable from the IT network, and provides end-to-end visibility into every command from operator submission through to PLC execution. A hybrid machine learning-based Intrusion Detection System runs asynchronously alongside the live command pipeline, detecting behavioural anomalies and mapping threats to the MITRE ATT&CK for ICS framework without introducing any latency into OT operations.

---

## Purdue Model Architecture

SIEMTRIX is structured around the Purdue Enterprise Reference Model, with each system component mapped to its corresponding level. This segmentation ensures that no lateral movement is possible between zones and that every command crosses a validation boundary before reaching the OT environment.

**Level 5 — Enterprise zone**  
Enterprise reporting, security posture summaries, and compliance audit views accessible to senior stakeholders.

**Level 4 — IT business zone**  
The web application and admin panel through which operators and administrators submit and manage OT commands. All user interactions are logged and role-based access control is enforced at this layer. No user at this level has direct access to any OT device.

**Level 3.5 — IT/OT DMZ (security zone)**  
The core security enforcement layer of SIEMTRIX. Every command submitted from the IT zone is received here, validated against a defined policy ruleset, and queued through RabbitMQ for controlled delivery. The ML-IDS engine also runs at this layer, analysing command log streams asynchronously and generating MITRE-tagged alerts. The automated incident response pipeline operates here as well, taking graduated action based on ML-IDS confidence scores.

**Level 3 — OT supervisory zone**  
The OT puller service, which is the only component permitted to retrieve commands from the DMZ queue. It operates on a pull-only basis, meaning the OT zone initiates all communication — the DMZ never pushes directly into OT. Retrieved commands are forwarded to the ScadaBR HMI for execution.

**Level 2 — Control systems**  
ScadaBR HMI receives validated commands from the OT puller and translates them into Modbus TCP read and write operations directed at the simulated PLC layer.

**Level 1 — Process layer**  
The OpenModSim PLC simulator, which receives and executes Modbus TCP commands from the HMI, returning register values and execution results.

**Level 0 — Field devices**  
Simulated sensors and actuators represented through the OpenModSim virtual environment.

**OT Sensor Zone**  
Suricata and Zeek run on a dedicated sensor VM with a passive traffic tap on the OT subnet. They monitor all traffic between the DMZ and OT zones without injecting any traffic of their own, generating signature-based and behavioural alerts that are forwarded to Splunk.

---

## Command Flow

Every command in SIEMTRIX follows a strictly controlled path from operator input to OT execution. No command can bypass any stage of this pipeline.

An operator submits a command through the web application, specifying the command type, target register, and function code. The backend assigns a unique Command ID to the submission and forwards it to the DMZ command validator. The validator checks the command against a policy ruleset covering function code whitelists, authorised register ranges per user role, and session frequency limits. Commands that fail any check are rejected immediately, logged to Splunk with a rejection reason, and the operator is notified. No rejected command enters the queue.

Commands that pass validation are placed on the RabbitMQ validated commands queue. The OT puller, running in the OT zone, polls this queue and retrieves commands in order. It forwards each command to ScadaBR, which executes the corresponding Modbus TCP operation on OpenModSim. The execution result — success or failure — is logged back to Splunk.

In parallel, the ML-IDS engine continuously polls Splunk log indexes and analyses recent command events for anomalous patterns. If the Isolation Forest layer detects a deviation above the configured threshold, the XGBoost classifier produces a final classification label and confidence score. An alert is written to the dmz_ml_ids Splunk index with the associated MITRE ATT&CK for ICS technique tag and the automated response pipeline evaluates the confidence score to determine the appropriate action.

---

## ML-IDS Detection Pipeline

The hybrid ML-IDS operates across three sequential detection layers, each serving a distinct purpose.

**Layer 1 — Static rule engine**  
The first filter is the DMZ command validator itself, which catches all known policy violations deterministically with zero ML overhead. Invalid function codes, out-of-range register addresses, and unauthorised user roles are rejected here before reaching the queue.

**Layer 2 — Isolation Forest (unsupervised anomaly detection)**  
An Isolation Forest model evaluates a sliding window of recent command events, scoring each window for statistical deviation from the established behavioural baseline. Features include inter-command timing, register access patterns, command type ratios, and queue latency distributions. This layer catches anomalous behaviour that static rules cannot — for example, a valid command issued at an unusual frequency or from an unusual sequence.

**Layer 3 — XGBoost (supervised classification)**  
Commands flagged by the Isolation Forest layer are passed to an XGBoost classifier trained on the operational dataset enriched with simulated attack samples. The classifier produces a label — normal, suspicious, or malicious — and a confidence score between 0 and 1. Each alert is tagged with the most probable MITRE ATT&CK for ICS technique ID, giving security analysts immediate context for every detection.

The ML-IDS operates entirely asynchronously. It reads from Splunk log streams after commands have already been delivered to the OT zone, meaning it introduces zero latency into the command execution pipeline regardless of processing load.

---

## MITRE ATT&CK for ICS Coverage

SIEMTRIX was validated against seven MITRE ATT&CK for ICS techniques through controlled attack simulations executed within the isolated testbed environment.

| Technique | Description | Attack vectors simulated |
|---|---|---|
| T0855 | Unauthorized command message | RBAC violation, function-code mismatch, read with value, missing user |
| T0884 | Connection probe | Invalid register, invalid device, register zero, register overflow |
| T0885 | Commonly used port | Value overflow, negative value, null write, boundary (65536) |
| T0859 / T1078 | Valid accounts | Unknown user, off-hours command |
| T0889 | Modify program | Long description, suspicious keyword |
| T0847 | Replication through removable media | Unusual function code |
| T0805 | Block serial COM | Unknown command type, unknown priority, malformed register |

All simulation scripts were designed to run exclusively within the isolated testbed environment. Each generated log event is tagged with a simulation flag to distinguish it from real operational data, and the resulting labeled dataset was used for ML model training and threshold calibration.

---

## Splunk SIEM Integration

Splunk serves as the central intelligence layer of SIEMTRIX, receiving structured log events from every component across all four security zones. Six dedicated indexes provide clear separation between data sources, reducing search overhead and making cross-zone correlation straightforward.

**it_app** captures all operator command submissions and administrator actions from the IT zone, including user role, command metadata, and session identifiers.

**dmz_validation** records every validation decision made by the DMZ command validator — approvals, rejections, rejection reasons, and queue timestamps. This index provides a complete audit trail of every command that passed through or was stopped at the DMZ boundary.

**ot_execution** captures command execution results from the OT zone, including execution status, PLC register values, function codes applied, and timestamps. Every command that reaches the OT environment has a corresponding record here.

**ot_ids_signature** receives Suricata alert events from the OT sensor zone, covering signature-matched detections on DMZ-to-OT traffic including Modbus anomalies and port scan activity.

**ot_ids_behavior** receives Zeek connection logs and behavioural analysis output from the OT sensor zone, providing session-level visibility into traffic patterns across the OT subnet.

**dmz_ml_ids** receives ML-IDS alert events generated by the Isolation Forest and XGBoost layers, including confidence scores, classification labels, MITRE ATT&CK technique tags, and associated command identifiers. This index also records all automated response actions taken by the incident response pipeline.

The Splunk correlation engine joins events across all indexes using the Command ID field, which persists from initial submission through every lifecycle stage to final execution. This allows a security analyst to trace any single command's complete journey — submission, validation decision, queue time, OT execution, and any ML alerts it triggered — from a single dashboard drill-down.

Pre-built dashboards cover command lifecycle tracking, end-to-end latency trends, OT execution status, SLA compliance monitoring, ML anomaly scoring, attack alert timelines with MITRE technique tags, and incident response status.

---

## Automated Incident Response

When the ML-IDS generates an alert, the response pipeline evaluates the confidence score against three configurable thresholds and takes the least disruptive action appropriate to the confidence level.

At Level 1, a dashboard notification is raised and the alert is logged. No command or session is affected and OT operations continue normally.

At Level 2, the flagged command is moved from the validated commands queue to a dedicated quarantine queue in RabbitMQ, preserving it for administrator review. An administrator notification is raised in Splunk. The administrator can release the command back to the validated queue or permanently reject it.

At Level 3, the source IP address or user session is added to a blocklist enforced by the DMZ command validator, preventing any further commands from that source from entering the pipeline. All pending commands from that source are quarantined simultaneously and a structured incident record is auto-generated in Splunk.

All response actions are written to the dmz_ml_ids index as audit log entries, maintaining a complete record of every automated decision made by the system.

---

## Key Results

| Metric | Result |
|---|---|
| Average end-to-end command latency | 72ms |
| SLA threshold | 200ms |
| Command delivery rate | 100% |
| DMZ validation rejection rate | 100% of invalid commands blocked |
| ML-IDS F1-score | 96.4% |
| False positive rate (shadow mode) | 4.2% |
| OT latency added by ML-IDS | 0ms |
| Peak latency at 500 commands/min | 148ms (within SLA) |
| MITRE ATT&CK techniques covered | 7 |
| Active Splunk indexes | 6 |

---

## Alignment and Standards

- **NIST SP 800-82 Rev. 2** — ICS security architecture, defense-in-depth, and continuous monitoring
- **Purdue Enterprise Reference Model** — zone segmentation and level mapping
- **MITRE ATT&CK for ICS** — attack scenario design and ML-IDS alert classification
- **IEC 62443** — referenced for future compliance alignment and productisation roadmap

---

## Future Work

- Transition ML-IDS from shadow mode observation to active enforcement after completing a full retraining cycle on attack simulation data
- Expand protocol support beyond Modbus TCP, DNP3, and OPC UA to include IEC 61850 for power systems and PROFINET for manufacturing environments
- Integrate a SOAR platform to enable fully automated incident remediation triggered by high-confidence ML alerts
- Validate the complete framework against physical PLC and HMI hardware in a hardware-in-the-loop testbed environment
- Extend ML detection with LSTM and Transformer models for improved temporal pattern recognition in OT command sequences
- Implement zero-trust architecture with certificate-based mutual TLS authentication across all zone boundaries

---

## Demo Video

[![Watch the Demo](https://img.youtube.com/vi/qrWha6SjirM/maxresdefault.jpg)](https://www.youtube.com/watch?v=qrWha6SjirM)

## Authors

**Zain Rashid** — [LinkedIn](https://www.linkedin.com/in/zainrashid04/) · [GitHub](https://github.com/zainos-blip)  
**Riaz Ahmed Ansari** — Air University, Islamabad

Supervisor: **Dr. Ammar Masood**, Dept. of Cyber Security, NCSA, Air University, Islamabad

---

## Disclaimer

SIEMTRIX is a research prototype developed and validated within an isolated academic testbed environment. It is not intended for direct deployment in live industrial environments without further validation, security hardening, and compliance review. All attack simulation components are provided strictly for controlled research and educational purposes within isolated environments.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
