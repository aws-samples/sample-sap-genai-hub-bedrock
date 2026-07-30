"""Warehouse operations agent used by the Lab 09 evaluation notebook.

This is the *same* agent built interactively in Lab 06 and deployed to AgentCore in
Labs 07/08 — a two-agent design:

- a **selector sub-agent** (``SelectorAPIAgentAsATool``) that reads the OpenAPI specs
  under ``assets/knowledgebase`` and picks which SAP API/endpoint fits a query, and
- the **warehouse agent** itself, which calls the selector, then the ``odata_caller``
  tool, to answer warehouse-operations questions.

Extracting it here keeps the notebook lean and — crucially — lets Stage 1 grade the
*real* deployed architecture instead of a simplified stand-in.

Two system prompts are provided so the notebook can grade the agent *before* and
*after* a prompt fix:

- ``WAREHOUSE_SYSTEM_PROMPT`` — the baseline (Lab 06/07/08) prompt. It mandates dynamic
  discovery: start with the selector, then read ``$metadata`` to learn the schema at
  runtime. That's flexible but wasteful — repeated ``$metadata`` reads and
  trial-and-error ``$filter`` guessing. This is the agent Stage 1 flags as inefficient.
- ``WAREHOUSE_SYSTEM_PROMPT_IMPROVED`` — the baseline plus the concrete schema the agent
  kept rediscovering (the entity set, real field names, warehouse ID, a worked
  ``$filter``/``$select`` example) and an instruction to skip the selector/``$metadata``
  round-trips for warehouse-stock queries. With these it queries correctly on the first call.

``build_warehouse_agent`` is the single factory both share; it wires up the selector
sub-agent and the warehouse agent for a given model.
"""

from pathlib import Path

import yaml
from strands import Agent, tool

from util.odata_tool import odata_caller

# Directory of OpenAPI specs the selector sub-agent reasons over. Matches Lab 06/07:
# the notebook runs from the repo root, so this relative path resolves to assets/knowledgebase.
KNOWLEDGEBASE_PATH = "./assets/knowledgebase"

# The OData service root for warehouse physical stock. The entity set lives one level
# below this — the agent must call it as the `endpoint`, not append it to the URL.
WAREHOUSE_ODATA_BASE_URL = (
    "https://sandbox.api.sap.com/s4hanacloud/sap/opu/odata4/sap/"
    "api_whse_physstockprod/srvd_a2x/sap/whsephysicalstockproducts/0001"
)

# TODO: Adjust capacity for your warehouse (used in evaluation scenarios).
WAREHOUSE_CAPACITY = 500


# --- Selector sub-agent prompt (from Lab 06) -------------------------------------------
def load_openapi_specs(path=KNOWLEDGEBASE_PATH):
    """Summarize every OpenAPI YAML under `path` into title/description/base-URLs/endpoints."""
    specs = []
    for file in Path(path).glob("*.y*ml"):
        with open(file, "r") as f:
            try:
                data = yaml.safe_load(f)
                base_urls = [
                    {"url": s.get("url"), "description": s.get("description", "")}
                    for s in data.get("servers", [])
                    if s.get("url")
                ]
                specs.append({
                    "file": file.name,
                    "title": data.get("info", {}).get("title"),
                    "description": data.get("info", {}).get("description"),
                    "paths": list(data.get("paths", {}).keys()),
                    "base_urls": base_urls or [{"url": "/", "description": "Default"}],
                })
            except Exception as e:  # noqa: BLE001 — malformed spec shouldn't break agent build
                print(f"Error parsing {file}: {e}")
    return specs


def specs_to_prompt_string(specs):
    """Render the spec summaries into the block injected into the selector's system prompt."""
    prompt_parts = []
    for spec in specs:
        base_url_str = ", ".join(
            f"{u['url']} ({u['description']})" for u in spec["base_urls"]
        )
        paths_str = ", ".join(spec["paths"])
        prompt_parts.append(
            f"API Spec: {spec['file']}\n"
            f"Title: {spec['title']}\n"
            f"Description: {spec['description']}\n"
            f"Base URLs: {base_url_str}\n"
            f"Endpoints: {paths_str}\n"
        )
    return "\n---\n".join(prompt_parts)


def _build_selector_prompt(path=KNOWLEDGEBASE_PATH):
    specs_prompt_string = specs_to_prompt_string(load_openapi_specs(path))
    return f"""
You are an API selection subagent.
Given a user query and the following list of OpenAPI specs, each with a title, description, base URLs, and available endpoints:

{specs_prompt_string}

Your task is to identify which API and specific endpoint is most appropriate to fulfill the user query.
Provide clear reasoning for your choice, referencing the API spec details provided.
If no suitable API is found, explain why.

Make sure to reply with the sandbox BASE URL.
"""


# --- Baseline warehouse prompt (identical to Lab 06/07/08) -----------------------------
# Mandates the selector + $metadata discovery loop, so the agent rediscovers the schema
# at runtime. Flexible, but this is exactly the wasteful trajectory Stage 1 catches.
WAREHOUSE_SYSTEM_PROMPT = """
You are an expert Warehouse Operations Manager for GlobalTech Manufacturing's Distribution Center (Warehouse 1750).
You have access to real-time SAP warehouse data through dynamic OData API exploration capabilities.

CORE CAPABILITIES:
1. API Structure Exploration: Dynamically discover available data fields and entities
2. Product Discovery: Find available products without hardcoded assumptions
3. Dynamic Querying: Construct intelligent OData queries based on user needs

APPROACH TO PROBLEM SOLVING:
- You must start by using the SelectorAPIAgentAsATool to help you determine which OData API to call
- Next use the $metadata endpoint that to understand the API that SelectorAPIAgentAsATool provides
- Use dynamic queries to discover information rather than making assumptions
- Leverage OData filtering, sorting, and selection to get precise answers
- You may need to do this multiple times. Always write what URL have constructed so user is informed.

PRODUCT KNOWLEDGE (can be expanded through discovery):
- WM-AN01: Advanced Sensors (high-precision electronic components)
- WM-AN02: Control Units (critical automation hardware)
- WM-AN03: Power Modules (electrical power management systems)
- WM-AN04: Communication Devices (networking and connectivity hardware)

COMMUNICATION STYLE:
- Be professional but conversational and succinct
- Explain your discovery process when exploring new data
- Provide specific, actionable insights with quantitative data
- If you know the user's preferences from memory, apply them without asking
- Do not use emojis

When users ask questions:
1. First determine what data you need to answer the question
2. Feel free to use the odata_caller tool as many times as needed to get the right information.
3. Construct appropriate OData queries to get the specific information needed
4. Analyze the results and provide comprehensive, intelligent responses

Focus on SAP S/4 HANA OData endpoints, warehouse management APIs, and supply chain operations.

Available tools:
- SelectorAPIAgentAsATool: Picks the right SAP OData API/endpoint for a query from the known OpenAPI specs
- odata_caller: Universal OData tool for SAP API interactions with built-in authentication and query parameter support
"""


# --- Improved prompt: baseline + the concrete schema the agent kept rediscovering. -----
# The KNOWN SCHEMA block is the fix — it lets the agent skip the selector + $metadata
# round-trips for warehouse-stock queries and filter server-side on the first call.
WAREHOUSE_SYSTEM_PROMPT_IMPROVED = WAREHOUSE_SYSTEM_PROMPT + """
KNOWN SCHEMA — use it directly for warehouse physical-stock queries. Do NOT call the
SelectorAPIAgentAsATool and do NOT read $metadata for these; you already know the API:
- base_url (service root): "{base_url}"
- endpoint (entity set): "WarehousePhysicalStockProducts"
- Warehouse ID: EWMWarehouse = "1750"
- Key fields:
  - Product                       (e.g. "WM-AN02")
  - EWMWarehouse                  (warehouse number, "1750")
  - EWMStorageBin                 (storage bin)
  - EWMStorageType                (storage type)
  - EWMStockType                  (stock type)
  - EWMStockQuantityInBaseUnit    (on-hand quantity, numeric)
  - EWMStockQuantityBaseUnit      (unit of measure)

Query the entity set on the FIRST call with a server-side $filter and $select — never fetch
everything and filter client-side. Worked example for a single product:
  odata_caller(
    base_url="{base_url}",
    endpoint="WarehousePhysicalStockProducts",
    operation="get",
    odata_params={{
      "$filter": "Product eq 'WM-AN02' and EWMWarehouse eq '1750'",
      "$select": "Product,EWMStockQuantityInBaseUnit,EWMStockQuantityBaseUnit,EWMStorageBin",
    }},
    auth_type="api_key",
    auth_env_var="SAP_S4HANA_PUBLIC_CLOUD_KEY",
  )
For all products, filter on EWMWarehouse eq '1750' alone; sort with $orderby when you need
low-stock items (e.g. "$orderby": "EWMStockQuantityInBaseUnit asc").
""".format(base_url=WAREHOUSE_ODATA_BASE_URL)


def build_warehouse_agent(model, system_prompt=WAREHOUSE_SYSTEM_PROMPT,
                          knowledgebase_path=KNOWLEDGEBASE_PATH):
    """Build the Lab 06 warehouse agent (selector sub-agent + odata_caller) for a model.

    This is the same two-agent architecture deployed in Labs 07/08. Local evaluation grades
    its query logic against a given system prompt — same model, tools, and selector, no
    memory. Pass ``WAREHOUSE_SYSTEM_PROMPT_IMPROVED`` to grade the fixed agent. The deployed,
    memory-enabled runtime is graded in Stage 2.
    """
    selector_agent = Agent(model=model, system_prompt=_build_selector_prompt(knowledgebase_path))

    @tool
    def SelectorAPIAgentAsATool(query: str) -> str:
        """Analyze available OpenAPI specs and select the most appropriate API and endpoint.

        Args:
            query: User query describing what they want to accomplish

        Returns:
            The selector sub-agent's API/endpoint recommendation.
        """
        return selector_agent(query).message

    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=[SelectorAPIAgentAsATool, odata_caller],
    )
