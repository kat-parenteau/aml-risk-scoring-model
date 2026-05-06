# aml-risk-scoring-model
A simulated bank enhancing detection of sanctions evasion and Russia-linked money laundering based on FINTRAC guidance (SIRA-2023-009). I researched and made this tool for self-education purposes only, so content may not be 100% correct or accurate!

## What this project does
 
When a bank, investment firm, or financial institution receives a wire transfer or opens an account for a new client, they are legally required to assess whether that transaction or entity might be connected to money laundering or sanctions violations. In Canada, this obligation is governed by the **Proceeds of Crime (Money Laundering) and Terrorist Financing Act (PCMLTFA)**, with oversight from **FINTRAC**.
 
This project implements a **risk-based detection model** that automates that assessment process for entities with potential links to Russia-related money laundering or sanctions evasion. It was designed based on the specific indicators, typologies, and red flags published by FINTRAC in their May 2023 Special Bulletin.
 
**In plain terms:** you feed the model a description of an entity (a company, individual, or transaction) and tell it which risk flags are present. The model assigns a composite risk score (0–100), tells you what monitoring rules have been triggered, and recommends exactly what a compliance officer should do next — including whether a Suspicious Transaction Report (STR) must be filed with FINTRAC.
 
---
 
## Why it matters
 
Russia's February 2022 invasion of Ukraine prompted a major escalation in international sanctions. Canada, alongside the EU, UK, and U.S., imposed restrictions. In response, sanctioned Russian individuals and entities have increasingly turned to sophisticated money laundering techniques to:
 
- Move assets out of Russia (shell companies and tax havens)
- Evade restrictions
- Obscure the true owners of assets through nominees and layered corporate structures
- Use cryptocurrency and ransomware proceeds to bypass the traditional banking system
Financial institutions that fail to detect these activities face serious regulatory and legal consequences. This model helps operationalise the FINTRAC guidance so that compliance teams can act on it systematically.
 
---
 
## Key concepts pulled directly from the FINTRAC bulletin
 
Every risk factor and monitoring rule in this model maps to a specific passage in FINTRAC SIRA-2023-009. Here is a plain-language breakdown:
 
### 1. Shell and front companies
**From the bulletin:** *"FINTRAC analysis has highlighted the continued use of intermediary jurisdictions to set up complex networks of shell and front companies… as a key feature of Russia-linked money laundering."*
 
Shell companies are legal entities with no real business operations that are used purely to hold assets or move money while hiding who actually owns them. The bulletin specifically calls out limited partnerships (LPs), limited liability partnerships (LLPs), and international business corporations (IBCs) registered in offshore financial centres.
 
**How the model uses this:** Any entity using one of these structures, particularly with no online presence or a generic/misspelled name, receives a high risk score and triggers rules for enhanced due diligence.
 
---
 
### 2. Non-resident banking
**From the bulletin:** *"A pattern of shell companies registered in traditional tax havens conducting international wire transfers using financial institutions in jurisdictions distinct from the company's registration."*
 
If a company is registered in, say, the British Virgin Islands, but does all its banking through a Canadian institution, and the money is ultimately flowing to Russia, that mismatch is a major red flag. The bulletin also flags "nested correspondent banking," where high-risk banks in jurisdictions that cater to Russian clients hold accounts at reputable international banks to make their payments look clean.
 
**How the model uses this:** Jurisdiction mismatches between registration and banking trigger medium-to-high severity rules and require source-of-funds documentation.
 
---
 
### 3. High-risk jurisdictions
**From the bulletin:** *"Particular attention should be paid to entities located in international trade hubs with noted anti-money laundering deficiencies, such as the United Arab Emirates, or in jurisdictions that have seen a recent decline in accountable governance and democratic development, such as Hong Kong."*
 
The bulletin also specifically mentions Turkey and Belarus as jurisdictions where Russian financial flows are concentrated.
 
**How the model uses this:** Any entity or counterparty based in these jurisdictions automatically adds points to the risk score and flags additional monitoring rules.
 
---
 
### 4. Nominee ownership (hiding who really owns the assets)
**From the bulletin:** *"Individuals seeking to launder the proceeds of crime and corruption, particularly those subject to sanctions… may also increasingly attempt to hide the ultimate beneficial ownership of assets by transferring legal ownership to family members, close associates and other nominees."*
 
This is a known sanctions-evasion technique: if you are personally sanctioned, put the house/account/company in your spouse's or child's name. The real owner still controls the asset even though the legal paperwork points somewhere else.
 
**How the model uses this:** Nominee structures trigger verification requirements and escalation to a senior compliance officer.
 
---
 
### 5. SPFS — Russia's alternative to SWIFT
**From the bulletin:** *"Russia has attempted to circumvent these measures by promoting the use of its home-grown alternative to SWIFT, the System for Transfer of Financial Messages (СПФС / SPFS)."*
 
Eight Russian banks were removed from SWIFT as of March 2023. SPFS was developed in 2014 and now has over 440 member institutions. Any financial intermediary connected to SPFS is a high-risk signal.
 
**How the model uses this:** SPFS connections trigger correspondent banking review rules and require full payment chain documentation.
 
---
 
### 6. Sanctions list exposure
**From the bulletin:** *"The Consolidated Canadian Autonomous Sanctions List is available for ease of reference… All Canadians must disclose to the RCMP the existence of property that is owned or controlled by a designated person."*
 
Canada's sanctions list names specific individuals and entities that Canadians are prohibited from dealing with, so a transaction linked to anyone on this list could be considered a criminal offense.
 
**How the model uses this:** Sanctions exposure is the single highest-scoring factor (20 points) and immediately triggers critical-severity rules and mandatory RCMP disclosure requirements.
 
---
 
### 7. Real estate transactions
**From the bulletin:** *"Since Russia's invasion of Ukraine, Russia-linked individuals and entities have increased the use of real-estate transactions for money laundering purposes, particularly in jurisdictions such as the United Arab Emirates and Türkiye."*
 
Property purchases are a classic money laundering vehicle: you buy real estate with dirty money, and when you sell it, the proceeds look legitimate.
 
**How the model uses this:** Real estate transactions in flagged jurisdictions add to the entity score and trigger high-risk controls.
 
---
 
### 8. Cryptocurrency and virtual assets
**From the bulletin:** *"Open source analysis of cryptocurrency transactions indicates that Russian entities and individuals represent a disproportionate share of cryptocurrency-enabled crime, including online fraud and ransomware."*
 
The bulletin specifically calls out:
- Transactions from IP addresses in Russia or Belarus
- Use of unlicensed brokers to "off-ramp" crypto
- Virtual currency mixing services, which is used to anonymise the source of funds
- The Bitzlato exchange
**How the model uses this:** Crypto exposures trigger a dedicated set of rules (R7–R10) including blockchain analytics review, and ransomware wallet traces trigger critical-level escalation.
 
---
 
### 9. Chain hopping
**From the bulletin:** *"A customer receives virtual currency from one or more private wallets, and immediately initiates multiple, rapid transfers for alternative virtual currencies (chain hopping) with no apparent related purpose, followed by an immediate withdrawal into fiat currency."*
 
This is a layering technique done by rapidly moving money across different cryptocurrencies, which makes it extremely difficult to trace the original source.
 
**How the model uses this:** Chain-hopping patterns trigger transaction pattern analysis rules and source-of-funds inquiries.
 
---
 
## How the risk score is calculated
 
The model assigns weighted points to each risk factor based on severity, then sums them to a composite score (capped at 100):
 
| Risk Level | Score Range | Controls Applied |
|---|---|---|
| Low | 1 – 24 | Standard KYC & screening |
| Medium | 25 – 49 | Enhanced due diligence screening |
| High | 50 – 74 | High-risk entity screening |
| Critical | 75 – 100 | Immediate freeze, mandatory suspicious transaction report filed, RCMP disclosure |
 
A **Suspicious Transaction Report (STR) is automatically flagged** when the score reaches 75 or higher, or when any "critical" severity monitoring rule is triggered (R6: Sanctions exposure, R10: Ransomware blockchain trace).
 
---
 
## How to run it
 
No external libraries required — pure Python 3.10+.
 
```bash
python aml_risk_scorer.py
```
 
This runs three demo entities of increasing risk level:
 
1. **Maple Ridge Trading Inc.** — clean domestic entity, no flags (score: 0)
2. **Solaris Global LP** — offshore shell with nominee ownership and UAE real estate (score: 75, High risk)
3. **Novex Digital Exchange Ltd.** — crypto exchange with sanctions link and ransomware trace (score: 100, Critical)
---
 
## How to assess your own entity
 
Import the module and build an `Entity` object using the available factor IDs:
 
```python
from aml_risk_scorer import Entity, score_entity, print_report
 
entity = Entity(
    name="Example Holdings Ltd.",
    entity_type="LLC",
    jurisdiction="United Arab Emirates",
    active_factors=[
        "shell_company",
        "high_risk_jurisdiction",
        "non_resident_banking",
        "nominee_ownership",
    ]
)
 
result = score_entity(entity)
print_report(result)
```
 
### Available risk factor IDs
 
| Factor ID | Name | Points |
|---|---|---|
| `shell_company` | Shell / front company involvement | 18 |
| `non_resident_banking` | Non-resident banking arrangement | 16 |
| `spfs_connection` | SPFS (Russian SWIFT alternative) connection | 18 |
| `sudden_volume_increase` | Sudden unexplained fund volume increase | 11 |
| `high_risk_jurisdiction` | High-risk / secrecy jurisdiction | 14 |
| `sanctions_link` | Sanctions list exposure | 20 |
| `nominee_ownership` | Nominee / proxy ownership | 15 |
| `real_estate_ml` | Real estate transaction (post-invasion) | 12 |
| `trade_based_ml` | Trade-based money laundering indicators | 13 |
| `crypto_exposure` | Virtual currency / crypto exposure | 16 |
| `ransomware_exposure` | Ransomware / cyber-crime blockchain exposure | 17 |
| `chain_hopping` | Chain-hopping / rapid conversion | 14 |
 
---
 
## Output example
 
```
========================================================================
  AML RISK ASSESSMENT REPORT
  FINTRAC Special Bulletin SIRA-2023-009 | Russia-Linked ML Detection
========================================================================
 
  Entity        : Novex Digital Exchange Ltd.
  Type          : Cryptocurrency Exchange
  Jurisdiction  : Hong Kong
 
  COMPOSITE SCORE  : 100 / 100
  RISK LEVEL       : [ CRITICAL ] Critical
  CONTROL TIER     : Critical
  STR REQUIRED     : ⚑ YES — File with FINTRAC
 
------------------------------------------------------------------------
  TRIGGERED MONITORING RULES
------------------------------------------------------------------------
 
  R6 [CRITICAL ] Sanctions list exposure
           ACTION: Freeze / block transaction immediately. Disclose to RCMP.
 
  R10 [CRITICAL ] Ransomware blockchain trace
           ACTION: Immediate transaction block. Report to FINTRAC and law enforcement.
...
```
 
---
 
## Regulatory references
 
| Reference | Description |
|---|---|
| FINTRAC SIRA-2023-009 | Special Bulletin on Russia-linked money laundering (May 2023) |
| PCMLTFA | Proceeds of Crime (Money Laundering) and Terrorist Financing Act |
| SEMA | Special Economic Measures Act (Canada) |
| JVCFOA | Justice for Victims of Corrupt Foreign Officials Act |
| Consolidated Sanctions List | [Canada's Autonomous Sanctions List](https://www.international.gc.ca/world-monde/international_relations-relations_internationales/sanctions/consolidated-consolide.aspx?lang=eng) |
| FINTRAC STR Guidance | [Reporting suspicious transactions to FINTRAC](https://www.fintrac-canafe.gc.ca/guidance-directives/transaction-operation/str-dod/str-dod-eng) |
 
---
 
## Disclaimer
 
This tool was made for self-education purposes and may not be 100% correct or accurate!
