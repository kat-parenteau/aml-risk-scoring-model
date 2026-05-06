"""
AML Risk Scoring Model — Russia-Linked Money Laundering Detection
=================================================================
Based on FINTRAC Special Bulletin SIRA-2023-009 (May 2023)
"Special Bulletin on Russia-linked money laundering activities"

This script implements a rule-based, risk-weighted scoring framework
to detect and assess suspicious transactions and entities that may be
linked to Russia-related money laundering or sanctions evasion!

Author note: All risk factors, monitoring rules, and escalation thresholds
are used directly from FINTRAC guidance, but this may not be 100% accurate.
"""

from dataclasses import dataclass, field
from typing import Optional
import json


# DATA STRUCTURES

@dataclass
class RiskFactor:
    """A single entity-level or behavioural risk indicator."""
    id: str
    name: str
    description: str
    score: int           # Weighted points (out of 100 total possible)
    category: str        # Corporate | Banking | Geography | Crypto | Asset | Trade | Behavioural
    triggers_rules: list[str] = field(default_factory=list)


@dataclass
class MonitoringRule:
    """A transaction monitoring rule that fires when related risk factors are present."""
    id: str
    name: str
    description: str
    severity: str        # critical | high | medium
    action_required: str


@dataclass
class Entity:
    """Represents a client, counterparty, or corporate structure being assessed."""
    name: str
    entity_type: str     # e.g. "LLC", "LP", "Individual", "Trust"
    jurisdiction: str
    active_factors: list[str] = field(default_factory=list)  # List of RiskFactor IDs


@dataclass
class ScoringResult:
    """The full output of a risk assessment run."""
    entity: Entity
    composite_score: int
    risk_level: str
    active_factors: list[RiskFactor]
    triggered_rules: list[MonitoringRule]
    control_tier: str
    recommended_actions: list[str]
    fintrac_str_required: bool


# RISK FACTOR LIBRARY

RISK_FACTORS: dict[str, RiskFactor] = {

    # --- CORPORATE STRUCTURE INDICATORS ---

    "shell_company": RiskFactor(
        id="shell_company",
        name="Shell / front company involvement",
        description=(
            "Entity uses LP, LLP, IBC, or similar opaque structure. Lacks verifiable "
            "online presence, real business activity, or has a generic / easily misspelled name. "
            "FINTRAC flags legal firms in offshore centres specialising in Russian clientele."
        ),
        score=18,
        category="Corporate",
        triggers_rules=["R1", "R2", "R3"]
    ),

    "nominee_ownership": RiskFactor(
        id="nominee_ownership",
        name="Nominee / proxy ownership",
        description=(
            "Legal ownership held by family members, close associates, or nominees to conceal "
            "the ultimate beneficial owner (UBO). FINTRAC notes this is increasingly used by "
            "sanctioned individuals to hide assets post-invasion."
        ),
        score=15,
        category="Corporate",
        triggers_rules=["R2", "R5"]
    ),

    # --- BANKING & PAYMENT INDICATORS ---

    "non_resident_banking": RiskFactor(
        id="non_resident_banking",
        name="Non-resident banking arrangement",
        description=(
            "Shell company registered in one jurisdiction banks through an unrelated jurisdiction. "
            "Includes nested correspondent banking where high-risk banks hold accounts in "
            "lower-risk jurisdictions to make international payments."
        ),
        score=16,
        category="Banking",
        triggers_rules=["R2", "R4"]
    ),

    "spfs_connection": RiskFactor(
        id="spfs_connection",
        name="SPFS (Russian SWIFT alternative) connection",
        description=(
            "Transaction or intermediary is connected to Russia's System for Transfer of "
            "Financial Messages (СПФС / SPFS), developed in 2014 after Crimea invasion. "
            "FINTRAC flags any SPFS-linked payment chain for enhanced scrutiny."
        ),
        score=18,
        category="Banking",
        triggers_rules=["R4", "R6"]
    ),

    "sudden_volume_increase": RiskFactor(
        id="sudden_volume_increase",
        name="Sudden unexplained fund volume increase",
        description=(
            "Accounts in jurisdictions associated with Russian financial flows showing a rapid, "
            "unexplained rise in transfer values with no clear economic or business rationale."
        ),
        score=11,
        category="Behavioural",
        triggers_rules=["R1", "R4"]
    ),

    # --- GEOGRAPHY & JURISDICTION INDICATORS ---

    "high_risk_jurisdiction": RiskFactor(
        id="high_risk_jurisdiction",
        name="High-risk / secrecy jurisdiction",
        description=(
            "Entity or transaction involves UAE, Turkey, Hong Kong, or Belarus — jurisdictions "
            "FINTRAC identifies as having AML deficiencies or notable Russian financial flows. "
            "Particular attention to recent spikes in new company formations in these locations."
        ),
        score=14,
        category="Geography",
        triggers_rules=["R1", "R3", "R4"]
    ),

    "sanctions_link": RiskFactor(
        id="sanctions_link",
        name="Sanctions list exposure",
        description=(
            "Direct or indirect connection to Canada's Consolidated Autonomous Sanctions List "
            "(under SEMA or JVCFOA). Includes Russian banks removed from SWIFT. All Canadians "
            "must disclose property of designated persons to the RCMP."
        ),
        score=20,
        category="Sanctions",
        triggers_rules=["R5", "R6"]
    ),

    # --- REAL ESTATE & ASSET INDICATORS ---

    "real_estate_ml": RiskFactor(
        id="real_estate_ml",
        name="Real estate transaction (post-invasion)",
        description=(
            "FINTRAC reports increased use of real estate, particularly in UAE and Türkiye, "
            "for money laundering since Russia's February 2022 invasion. Purchases without "
            "clear economic rationale are flagged."
        ),
        score=12,
        category="Asset",
        triggers_rules=["R3", "R6"]
    ),

    # --- TRADE-BASED INDICATORS ---

    "trade_based_ml": RiskFactor(
        id="trade_based_ml",
        name="Trade-based money laundering indicators",
        description=(
            "Over/under-invoicing, phantom shipments, or misrepresented goods transiting "
            "high-risk jurisdictions. Russia-linked ML known to use trade channels to move "
            "and hide assets internationally."
        ),
        score=13,
        category="Trade",
        triggers_rules=["R3", "R5"]
    ),

    # --- CRYPTOCURRENCY & VIRTUAL ASSET INDICATORS ---

    "crypto_exposure": RiskFactor(
        id="crypto_exposure",
        name="Virtual currency / crypto exposure",
        description=(
            "Transactions routed through crypto exchanges in Russia or high-risk jurisdictions, "
            "or wallets linked to sanctioned entities. FINTRAC notes Russian entities represent "
            "a disproportionate share of cryptocurrency-enabled crime including ransomware."
        ),
        score=16,
        category="Crypto",
        triggers_rules=["R7", "R8", "R9"]
    ),

    "ransomware_exposure": RiskFactor(
        id="ransomware_exposure",
        name="Ransomware / cyber-crime blockchain exposure",
        description=(
            "Virtual currency linked to ransomware actors via blockchain tracing software. "
            "FINTRAC highlights Conti (a Russia-linked Ransomware-as-a-Service group) and "
            "Bitzlato (identified by U.S. FinCEN as a primary money laundering concern in 2023)."
        ),
        score=17,
        category="Crypto",
        triggers_rules=["R7", "R8", "R9", "R10"]
    ),

    "chain_hopping": RiskFactor(
        id="chain_hopping",
        name="Chain-hopping / rapid virtual currency conversion",
        description=(
            "Customer receives virtual currency then immediately converts across multiple "
            "alternative currencies (chain hopping) with no apparent purpose, followed by "
            "immediate fiat withdrawal. Classic layering technique."
        ),
        score=14,
        category="Crypto",
        triggers_rules=["R8", "R9"]
    ),
}



# TRANSACTION MONITORING RULES

MONITORING_RULES: dict[str, MonitoringRule] = {

    "R1": MonitoringRule(
        id="R1",
        name="Unusual fund volume surge",
        description=(
            "Account linked to a Russia-flow jurisdiction shows sudden unexplained rise in "
            "transfer value. No clear economic rationale. Flag for enhanced transaction review."
        ),
        severity="high",
        action_required="Enhanced transaction monitoring; request source-of-funds documentation."
    ),

    "R2": MonitoringRule(
        id="R2",
        name="Opaque corporate structure",
        description=(
            "Entity uses LP, LLP, or IBC with layered ownership across offshore centres. "
            "No verifiable online presence or legitimate business activity identified."
        ),
        severity="high",
        action_required="Full UBO mapping required; reject nominee-only structures. EDD mandatory."
    ),

    "R3": MonitoringRule(
        id="R3",
        name="Jurisdiction mismatch (non-resident banking)",
        description=(
            "Entity registration jurisdiction differs materially from banking jurisdiction. "
            "No plausible economic explanation. Consistent with non-resident banking typology."
        ),
        severity="medium",
        action_required="Obtain written business rationale; review correspondent bank chain."
    ),

    "R4": MonitoringRule(
        id="R4",
        name="Correspondent banking / SPFS red flag",
        description=(
            "Canadian FI used as a transit point for transfers connected to Russian-flow "
            "intermediaries or SPFS-linked institutions. Nested correspondent banking risk."
        ),
        severity="high",
        action_required=(
            "Review all correspondent relationships. Obtain full SWIFT/SPFS payment chain. "
            "Report to FINTRAC if ML/TF grounds exist."
        )
    ),

    "R5": MonitoringRule(
        id="R5",
        name="Beneficial ownership concealment",
        description=(
            "Legal ownership transferred to nominees. UBO cannot be verified through standard "
            "KYC procedures. Consistent with sanctions-evasion typology."
        ),
        severity="high",
        action_required=(
            "Senior compliance officer approval required. Independent UBO verification. "
            "Consider account refusal or exit."
        )
    ),

    "R6": MonitoringRule(
        id="R6",
        name="Sanctions list exposure",
        description=(
            "Entity or transaction has direct or indirect link to a person or entity on "
            "Canada's Consolidated Autonomous Sanctions List (SEMA / JVCFOA)."
        ),
        severity="critical",
        action_required=(
            "Freeze / block transaction immediately. Disclose to RCMP per SEMA obligations. "
            "File STR with FINTRAC. Notify Legal and Sanctions Counsel."
        )
    ),

    "R7": MonitoringRule(
        id="R7",
        name="Sanctioned-jurisdiction IP or wallet",
        description=(
            "Virtual currency transaction originates from or is destined for IP addresses "
            "or wallet addresses in Russia, Belarus, or comprehensively sanctioned jurisdictions."
        ),
        severity="high",
        action_required="Block transaction. Blockchain analytics review. STR to be considered."
    ),

    "R8": MonitoringRule(
        id="R8",
        name="Mixer / tumbler service exposure",
        description=(
            "Customer has direct or indirect transactional exposure to a virtual currency "
            "mixing or tumbling service — a classic obfuscation tool."
        ),
        severity="high",
        action_required="Blockchain tracing required. EDD on customer. STR consideration."
    ),

    "R9": MonitoringRule(
        id="R9",
        name="Rapid chain-hopping pattern",
        description=(
            "Multiple rapid conversions across virtual currencies followed by immediate fiat "
            "withdrawal with no apparent business purpose. Classic layering technique."
        ),
        severity="medium",
        action_required="Transaction pattern analysis. Source-of-funds inquiry. EDD."
    ),

    "R10": MonitoringRule(
        id="R10",
        name="Ransomware blockchain trace",
        description=(
            "Blockchain analytics identifies transaction exposure to known ransomware wallet "
            "addresses (e.g. Conti, Bitzlato-linked). FINTRAC / U.S. FinCEN flagged."
        ),
        severity="critical",
        action_required=(
            "Immediate transaction block. Report to FINTRAC and relevant law enforcement. "
            "Retroactive transaction review. Notify Legal."
        )
    ),
}


# CONTROL TIERS

CONTROL_TIERS = [
    {
        "tier": "Baseline",
        "min_score": 0,
        "label": "Standard KYC & screening",
        "actions": [
            "Screen entity against Canada's Consolidated Autonomous Sanctions List (SEMA / JVCFOA).",
            "Verify UBO to at least 25% ownership threshold.",
            "Confirm counterparty and jurisdiction risk against FINTRAC typologies.",
            "Apply standard transaction monitoring thresholds.",
        ]
    },
    {
        "tier": "Enhanced",
        "min_score": 25,
        "label": "Enhanced Due Diligence (EDD)",
        "actions": [
            "Obtain independent UBO documentation; reject nominee-only structures.",
            "Verify source of funds and source of wealth independently.",
            "Apply adverse media screening for Russia / Belarus / sanctioned jurisdiction links.",
            "Escalate to Senior Compliance Officer before account opening or processing.",
            "Increase monitoring frequency and lower transaction alert thresholds.",
        ]
    },
    {
        "tier": "High-Risk",
        "min_score": 50,
        "label": "High-Risk Entity Controls",
        "actions": [
            "Apply continuous, real-time transaction monitoring.",
            "Require VP-level relationship sponsor sign-off.",
            "Request full SWIFT / SPFS payment chain documentation for all wire transfers.",
            "Cross-reference virtual currency addresses via blockchain analytics.",
            "File a Suspicious Transaction Report (STR) to FINTRAC if reasonable grounds exist.",
            "Notify Global Affairs Canada of property linked to designated persons.",
        ]
    },
    {
        "tier": "Critical",
        "min_score": 75,
        "label": "Critical / Sanctions Breach Controls",
        "actions": [
            "Immediately freeze or block relevant transactions pending compliance review.",
            "Submit STR to FINTRAC as soon as practicable (reference: SIRA-2023-009).",
            "Disclose property and proposed transactions to the RCMP as required under SEMA.",
            "Notify Legal and Sanctions Counsel; assess exposure under SEMA / JVCFOA / UN Act.",
            "Conduct retroactive transaction review for the prior 24 months.",
            "Escalate to Board Risk Committee; consider full account termination.",
            "Retain all documentation for a minimum of 5 years for regulatory examination.",
        ]
    },
]

# SCORING ENGINE

def score_entity(entity: Entity) -> ScoringResult:
    """
    Run a full AML risk assessment on an entity.
    Takes in an Entity object with a list of active risk factor IDs.
    Returns a ScoringResult with composite score, risk level, triggered rules, recommended controls, and STR guidance.
    """

    # Resolve active RiskFactor objects
    active_factors = [
        RISK_FACTORS[fid]
        for fid in entity.active_factors
        if fid in RISK_FACTORS
    ]

    # Calculate score (capped at 100)
    raw_score = sum(f.score for f in active_factors)
    composite_score = min(raw_score, 100)

    # Determine risk level
    risk_level = _get_risk_level(composite_score)

    # Identify triggered monitoring rules
    triggered_rule_ids: set[str] = set()
    for factor in active_factors:
        triggered_rule_ids.update(factor.triggers_rules)

    triggered_rules = [
        MONITORING_RULES[rid]
        for rid in sorted(triggered_rule_ids)
        if rid in MONITORING_RULES
    ]

    # Select the right control tier
    control = _get_control_tier(composite_score)

    # Suspicious transaction report is required if any critical rule is triggered OR the score >= 75
    str_required = (
        composite_score >= 75
        or any(r.severity == "critical" for r in triggered_rules)
    )

    return ScoringResult(
        entity=entity,
        composite_score=composite_score,
        risk_level=risk_level,
        active_factors=active_factors,
        triggered_rules=triggered_rules,
        control_tier=control["tier"],
        recommended_actions=control["actions"],
        fintrac_str_required=str_required,
    )


def _get_risk_level(score: int) -> str:
    if score == 0:
        return "No Risk Identified"
    elif score < 25:
        return "Low"
    elif score < 50:
        return "Medium"
    elif score < 75:
        return "High"
    else:
        return "Critical"


def _get_control_tier(score: int) -> dict:
    applicable = [t for t in CONTROL_TIERS if score >= t["min_score"]]
    return applicable[-1]  # Return the highest tier that applies



# REPORT PRINTER

def print_report(result: ScoringResult) -> None:
    """Print a formatted AML risk assessment report to the console."""
    # oh man this took forever :(
    DIVIDER = "-" * 70
    THIN    = "." * 40

    RISK_COLOURS = {
        "No Risk Identified": "",
        "Low":      "[ LOW      ]",
        "Medium":   "[ MEDIUM   ]",
        "High":     "[ HIGH     ]",
        "Critical": "[ CRITICAL ]",
    }

    print(f"\n{DIVIDER}")
    print("  AML RISK ASSESSMENT REPORT")
    print(f"  FINTRAC Special Bulletin SIRA-2023-009 | Russia-Linked ML Detection")
    print(DIVIDER)

    print(f"\n  Entity        : {result.entity.name}")
    print(f"  Type          : {result.entity.entity_type}")
    print(f"  Jurisdiction  : {result.entity.jurisdiction}")
    print(f"\n  COMPOSITE SCORE  : {result.composite_score} / 100")
    print(f"  RISK LEVEL       : {RISK_COLOURS.get(result.risk_level, '')} {result.risk_level}")
    print(f"  CONTROL TIER     : {result.control_tier}")
    print(f"  STR REQUIRED     : {'⚑ YES — File with FINTRAC' if result.fintrac_str_required else 'No (monitor and reassess)'}")

    print(f"\n{THIN}")
    print("  ACTIVE RISK FACTORS")
    print(THIN)
    if result.active_factors:
        for f in result.active_factors:
            print(f"\n  [{f.score:>2} pts] {f.name}  ({f.category})")
            print(f"         {f.description[:75]}...")
    else:
        print("\n  No risk factors selected.")

    print(f"\n{THIN}")
    print("  TRIGGERED MONITORING RULES")
    print(THIN)
    if result.triggered_rules:
        for r in result.triggered_rules:
            sev_tag = f"[{r.severity.upper():<8}]"
            print(f"\n  {r.id} {sev_tag} {r.name}")
            print(f"           {r.description[:70]}...")
            print(f"           ACTION: {r.action_required[:70]}")
    else:
        print("\n  No rules triggered.")

    print(f"\n{THIN}")
    print(f"  RECOMMENDED CONTROLS  ({result.control_tier} tier)")
    print(THIN)
    for i, action in enumerate(result.recommended_actions, 1):
        print(f"\n  {i}. {action}")

    print(f"\n{DIVIDER}\n")



# DEMO :)

def run_demo():
    """
    Demonstrates the scoring engine on three illustrative entities of
    increasing risk, based on typologies from FINTRAC SIRA-2023-009.
    """

    print("\n" + "=" * 72)
    print("  DEMO: AML RISK SCORING MODEL — RUSSIA-LINKED ML")
    print("  Based on FINTRAC Special Bulletin SIRA-2023-009 (May 2023)")
    print("=" * 72)

    # -------------------------------------------------------------------
    # ENTITY 1: Low-risk baseline, domestic business, no red flags
    # -------------------------------------------------------------------
    entity_1 = Entity(
        name="Maple Ridge Trading Inc.",
        entity_type="Corporation",
        jurisdiction="Ontario, Canada",
        active_factors=[]   # No risk factors present
    )

    # -------------------------------------------------------------------
    # ENTITY 2: High-risk, offshore shell with correspondent banking
    # Mirrors FINTRAC typology: LP in tax haven, non-resident banking,
    # UAE real estate, no clear business rationale
    # -------------------------------------------------------------------
    entity_2 = Entity(
        name="Solaris Global LP",
        entity_type="Limited Partnership",
        jurisdiction="British Virgin Islands",
        active_factors=[
            "shell_company",
            "non_resident_banking",
            "high_risk_jurisdiction",
            "nominee_ownership",
            "real_estate_ml",
        ]
    )

    # -------------------------------------------------------------------
    # ENTITY 3: Critical, sanctions-adjacent crypto with ransomware trace
    # Mirrors FINTRAC / FinCEN Bitzlato typology: crypto exchange linked
    # to sanctioned individuals, chain-hopping, ransomware wallet exposure
    # -------------------------------------------------------------------
    entity_3 = Entity(
        name="Novex Digital Exchange Ltd.",
        entity_type="Cryptocurrency Exchange",
        jurisdiction="Hong Kong",
        active_factors=[
            "shell_company",
            "spfs_connection",
            "sanctions_link",
            "crypto_exposure",
            "ransomware_exposure",
            "chain_hopping",
            "high_risk_jurisdiction",
        ]
    )

    for entity in [entity_1, entity_2, entity_3]:
        result = score_entity(entity)
        print_report(result)
        

# RUN

if __name__ == "__main__":
    run_demo()
