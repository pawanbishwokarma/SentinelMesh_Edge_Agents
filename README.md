# SentinelMesh Final Project

SentinelMesh is an autonomous Tier 1 SOC alert triage agent for IoT network flow alerts. It uses an LLM with grounded tools to classify alerts, add MITRE ATT&CK context, score severity, recommend analyst-approved response actions, and evaluate performance with traces and manual review.

## Project deliverables

### Technical artifacts

1. `notebooks/01_data_pipeline.ipynb`  
   Data pipeline that loads the CIC IoT 2023 subset, builds a stratified sample, renders raw network flow rows into plain English alerts, and writes Unity Catalog tables.

2. `notebooks/sentinelmesh_agent.ipynb` and `src/sentinelmesh_agent.py`  
   Reusable agent definition with system prompt, LLM endpoint configuration, tool definitions, tool execution loop, and graceful rejection behavior.

3. `notebooks/02_agent_definition_and_traces.ipynb`  
   Agent demonstration notebook with MLflow tracing, five example traces, two model comparison, graceful rejection examples, and deterministic exact plus coarse evaluation.

4. `notebooks/03_evaluation.ipynb`  
   Final evaluation notebook with answer sheet generation, fallback LLM judge, documented MLflow make_judge endpoint limitations, manual deterministic judge, human review table, and final MLflow metrics logging.

### Business artifacts

1. `presentation/SentinelMesh_Final_Project_Deck.pptx`  
   Final slide deck for the business presentation.

2. `presentation/SentinelMesh_Final_Presentation.pdf`  
   PDF export of the final deck.

The video presentation is submitted separately as required by the assignment.

## Core architecture

SentinelMesh has five layers:

1. Data pipeline: CIC IoT 2023 subset to enriched alert text and Unity Catalog tables.
2. Agent: LLM plus system prompt and tool calling loop.
3. Tools: MITRE lookup, severity scoring, and action recommendation.
4. Observability: MLflow traces for LLM calls and tool calls.
5. Evaluation: fallback LLM judge, manual deterministic judge, human review, and metrics logging.

## Unity Catalog tables created by the pipeline

The data pipeline writes the following tables:

- `main.default.cic_alerts_raw`
- `main.default.cic_alerts_sample`
- `main.default.mitre_reference`
- `main.default.cic_label_family_map`

The agent never sees the true label in the rendered alert text. Labels are used only for evaluation.

## Models used

- `databricks-gpt-oss-120b`
- `databricks-gpt-oss-20b`
- `anthropic-claude-sonnet-4`
- `databricks-claude-opus-4-8` was attempted for judge evaluation but was unavailable in the workspace due to endpoint rate limits.

## Tools used by the agent

- `lookup_mitre_context`: queries the MITRE reference table in Unity Catalog.
- `score_severity`: scores alert severity based on attack family and packet rate.
- `recommend_action`: maps severity and mitigation context to analyst-approved response guidance.

## Evaluation summary

The final evaluation used a 12 alert evaluation set. The manual deterministic judge was used as the primary reproducible score because MLflow `make_judge` attempts encountered endpoint rate limits or structured `response_schema` compatibility issues.

Reported results from the final evaluation notebook:

- Exact family accuracy: 2/12 or 17 percent, unless rerun output shows the updated 3/12 value.
- Coarse triage accuracy: 7/12 or 58 percent.
- Fallback LLM judge pass rate: captured in `03_evaluation.ipynb` if the fallback judge completed successfully.

The result shows that SentinelMesh is more useful as a Tier 1 SOC triage assistant for broad operational routing than as a precise standalone classifier. Exact family classification remains difficult from single row flow statistics because several families, especially DDoS, DoS, and Mirai, share similar observable patterns.

## How to run

Run the notebooks in Databricks in this order:

1. Import or create `sentinelmesh_agent.py` in the same Databricks workspace folder as the notebooks.
2. Run `01_data_pipeline.ipynb` to create Unity Catalog tables.
3. Run `02_agent_definition_and_traces.ipynb` to generate traces and model comparison outputs.
4. Run `03_evaluation.ipynb` to generate the answer sheet, evaluate outputs, show human review, and log final metrics.

Expected raw data path:

```text
/Volumes/main/default/raw_data/SentinelMesh_Final_Subset.csv
```

The dataset file is not included in this repository. It should be loaded into the Databricks volume path above before running the pipeline.

## AI usage disclosure

AI tools were used to assist with code scaffolding, debugging, documentation, and presentation structure. All code was reviewed, tested, modified, and interpreted by the project author. The final analysis, results, and conclusions are based on the Databricks notebook executions and MLflow outputs.
