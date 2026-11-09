# AI Security Automation: Prompt Injection Prevention Gateway (v2)

An enterprise-grade AI input inspection proxy built in Python to safeguard Corporate Large Language Models (LLMs) from adversarial prompt engineering.

## 🚀 Key Features
- **Signature-Based Inspection:** Scans raw user inputs using strict regex layers to mitigate instruction overrides and system prompt leakage attempts.
- **Advanced De-obfuscation Check:** Features embedded Base64 decoding algorithms to unwrap and inspect hidden or obfuscated payloads designed to bypass common controls.
- **SOC Integration Ready:** Outputs structured telemetry in clean JSON format (`ai_security_alerts.log`) for rapid SIEM ingestion and automated security alerting.
- **Framework Realignment:** Directly mapped against the **OWASP LLM01: Prompt Injection** matrix and **MITRE ATT&CK T1059** techniques.

## 🧪 Simulation Log Output
When an adversarial payload is flagged, the gateway denies transaction execution and generates granular incident logs:

```json
{
    "timestamp": "2026-11-09 01:49:15",
    "event_type": "AI_PROMPT_INJECTION_ATTEMPT",
    "mitre_attack_mapping": "T1059 (Command and Scripting Interpreter)",
    "owasp_llm_risk": "LLM01: Prompt Injection",
    "severity": "CRITICAL",
    "obfuscation_detected": true,
    "detected_signatures": [
        "Instruction Override (Hidden in Base64)",
        "System Prompt Leakage (Hidden in Base64)"
    ]
}
```

## 🛠️ Usage
To run the automated security gateway simulator:
```bash
python3 ai_security_gateway.py
```
