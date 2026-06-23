import json
from databricks.sdk import WorkspaceClient

LLM_ENDPOINT = "databricks-gpt-oss-120b"
SMALL_LLM_ENDPOINT = "databricks-gpt-oss-20b"

openai_client = WorkspaceClient().serving_endpoints.get_open_ai_client()

SYSTEM_PROMPT = """You are SentinelMesh, an autonomous Tier 1 SOC alert triage assistant.
You analyze network flow alerts and produce a triage decision for a human analyst to approve.

Your workflow for each alert:
1. Read the alert and decide the most likely attack family from this list ONLY:
   DDOS_FLOOD, DOS_FLOOD, MIRAI, RECON, VULNERABILITYSCAN, SPOOFING, BRUTEFORCE, WEB_ATTACK, MALWARE, BENIGN.
2. Call lookup_mitre_context with that family to get MITRE ATT&CK context.
3. Call score_severity with the family and the observed packets per second.
4. Call recommend_action with the family, severity score, and mitigation text.
5. Give a final triage summary: predicted attack family, MITRE technique, severity, and recommended action.

Base your attack family judgment ONLY on the observable traffic described in the alert:
protocol, packet rate, flags, packet sizes, and inter arrival time. You will never be told the true answer.

If the user input is NOT a network security alert, politely decline and explain that you only triage security alerts.
Do not call tools for non alert inputs.
"""


def _get_family(kwargs):
    for key in ["attack_family", "predicted_attack_family", "family", "attack_type"]:
        if key in kwargs:
            return kwargs[key]
    return "UNKNOWN"


def lookup_mitre_context(**kwargs) -> dict:
    attack_family = _get_family(kwargs)

    query = f"""
        SELECT technique_id, technique_name, description, detection, mitigation
        FROM main.default.mitre_reference
        WHERE attack_family = '{attack_family.upper()}'
    """

    result = spark.sql(query).toPandas()

    if len(result) == 0:
        return {
            "attack_family": attack_family,
            "technique_id": "UNKNOWN",
            "technique_name": "Unknown / unmapped",
            "description": "No MITRE mapping found for this attack family.",
            "detection": "N/A",
            "mitigation": "Escalate to a human analyst for manual review."
        }

    row = result.iloc[0]

    return {
        "attack_family": attack_family,
        "technique_id": row["technique_id"],
        "technique_name": row["technique_name"],
        "description": row["description"],
        "detection": row["detection"],
        "mitigation": row["mitigation"]
    }


def score_severity(**kwargs) -> dict:
    attack_family = _get_family(kwargs)

    packets_per_sec = kwargs.get(
        "packets_per_sec",
        kwargs.get("packets_per_second", kwargs.get("rate", 0))
    )

    family_base = {
        "BENIGN": 1,
        "RECON": 4,
        "VULNERABILITYSCAN": 4,
        "SPOOFING": 6,
        "BRUTEFORCE": 6,
        "WEB_ATTACK": 7,
        "DOS_FLOOD": 7,
        "DDOS_FLOOD": 8,
        "MIRAI": 8,
        "MALWARE": 9
    }

    base = family_base.get(attack_family.upper(), 5)

    try:
        packets_per_sec = float(packets_per_sec)
    except Exception:
        packets_per_sec = 0

    if packets_per_sec > 10000:
        intensity_bump = 2
    elif packets_per_sec > 1000:
        intensity_bump = 1
    else:
        intensity_bump = 0

    if attack_family.upper() == "BENIGN":
        intensity_bump = 0

    score = min(base + intensity_bump, 10)

    rationale = (
        f"Base {base} for {attack_family}"
        + (f", +{intensity_bump} for {packets_per_sec:,.0f} packets per second" if intensity_bump else "")
        + f" gives final severity {score}/10."
    )

    return {
        "severity_score": score,
        "rationale": rationale
    }


def recommend_action(**kwargs) -> dict:
    attack_family = _get_family(kwargs)

    severity_score = kwargs.get("severity_score", kwargs.get("severity", 5))
    mitigation = kwargs.get("mitigation", "Refer to MITRE guidance.")

    try:
        severity_score = int(severity_score)
    except Exception:
        severity_score = 5

    if severity_score >= 8:
        tier = "CRITICAL"
        action = "Immediate containment recommended"
    elif severity_score >= 5:
        tier = "ELEVATED"
        action = "Investigate and prepare to contain"
    elif severity_score >= 3:
        tier = "LOW"
        action = "Monitor and log for pattern analysis"
    else:
        tier = "INFORMATIONAL"
        action = "No action needed; continue normal monitoring"

    if attack_family.upper() == "BENIGN":
        tier = "INFORMATIONAL"
        action = "Benign traffic; no action required"

    recommendation = (
        f"[{tier}] {action}. "
        f"Suggested mitigation from MITRE: {mitigation} "
        f"Awaiting human analyst approval before any action is taken."
    )

    return {
        "urgency_tier": tier,
        "recommendation": recommendation
    }


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_mitre_context",
            "description": "Look up MITRE ATT&CK context for a predicted attack family.",
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_family": {
                        "type": "string",
                        "description": "Predicted attack family."
                    }
                },
                "required": ["attack_family"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "score_severity",
            "description": "Score alert severity from 1 to 10 using attack family and packet rate.",
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_family": {
                        "type": "string",
                        "description": "Predicted attack family."
                    },
                    "packets_per_sec": {
                        "type": "number",
                        "description": "Observed packets per second."
                    }
                },
                "required": ["attack_family", "packets_per_sec"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "recommend_action",
            "description": "Recommend a human approved response action.",
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_family": {
                        "type": "string",
                        "description": "Predicted attack family."
                    },
                    "severity_score": {
                        "type": "integer",
                        "description": "Severity score."
                    },
                    "mitigation": {
                        "type": "string",
                        "description": "MITRE mitigation guidance."
                    }
                },
                "required": ["attack_family", "severity_score", "mitigation"]
            }
        }
    }
]


TOOL_FUNCTIONS = {
    "lookup_mitre_context": lookup_mitre_context,
    "score_severity": score_severity,
    "recommend_action": recommend_action
}


def extract_text(content):
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = []

        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    text_parts.append(item.get("text", ""))

                if item.get("type") == "reasoning":
                    summaries = item.get("summary", [])
                    for summary in summaries:
                        if isinstance(summary, dict) and summary.get("type") == "summary_text":
                            text_parts.append(summary.get("text", ""))

        if text_parts:
            return "\n".join(text_parts)

    return str(content)


def run_triage(alert_text, model=LLM_ENDPOINT, max_steps=6):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": alert_text}
    ]

    for step in range(max_steps):
        response = openai_client.chat.completions.create(
            model=model,
            messages=messages,
            tools=TOOLS
        )

        msg = response.choices[0].message

        if not msg.tool_calls:
            return extract_text(msg.content)

        messages.append(msg)

        for tool_call in msg.tool_calls:
            fn_name = tool_call.function.name

            if fn_name not in TOOL_FUNCTIONS:
                result = {
                    "error": "Unknown tool requested",
                    "tool_name": fn_name,
                    "message": "The requested tool is not available."
                }
            else:
                try:
                    fn_args = json.loads(tool_call.function.arguments)
                    result = TOOL_FUNCTIONS[fn_name](**fn_args)
                except Exception as e:
                    result = {
                        "error": "Tool execution failed",
                        "tool_name": fn_name,
                        "message": str(e)
                    }

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result, default=str)
            })

    return "Triage did not complete within the step limit."


print("sentinelmesh_agent.py loaded successfully.")