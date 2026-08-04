"""Warehouse operations agent used by the Lab 09 evaluation notebook.

This module ships **two architectures** so the notebook can grade one against the other:

**Baseline** (``build_warehouse_agent`` + ``WAREHOUSE_SYSTEM_PROMPT``) — the two-agent
design built interactively in Lab 06 and deployed to AgentCore in Lab 07:

- a **selector sub-agent** (``SelectorAPIAgentAsATool``) that reads the OpenAPI specs
  under ``assets/knowledgebase`` and picks which SAP API/endpoint fits a query, and
- the **warehouse agent** itself, which calls the selector, then reads ``$metadata`` and
  hand-constructs ``$filter``/``$select`` calls to ``odata_caller``.

That dynamic-discovery loop is flexible but wasteful: for the *same* warehouse-stock
question it re-reads ``$metadata``, guesses ``$filter``s by trial and error, and pays for
a selector LLM round-trip every time. Stage 1's trajectory judge flags exactly this — it
scores Correctness 1.0 but names three wasteful patterns: repeated ``$metadata``
rediscovery, trial-and-error ``$filter`` guessing, and an unnecessary selector call.

**Improved** (``build_improved_warehouse_agent`` + ``WAREHOUSE_ROUTER_SYSTEM_PROMPT``) —
the eval-driven refactor. Each of the three findings is knowable at *design time*, not
runtime, so we move that knowledge into code:

- a deep **``get_warehouse_stock``** tool encodes the service root, entity set, field
  names, warehouse ID, and server-side ``$filter``/``$select``/``$orderby`` construction.
  The agent stops writing OData for the hot path — it fills two typed parameters and gets
  the answer in **one** call, no ``$metadata``, no selector, no failed filters.
- the selector sub-agent and generic ``odata_caller`` are **kept as a fallback**: for
  genuinely novel or off-path questions the agent still discovers the right API
  dynamically. The improved prompt is therefore a **router** — deep tool for warehouse
  stock, dynamic discovery for everything else. The Lab 06/07 selector was the right call
  for open-ended exploration; it just shouldn't sit on the one hot path we benchmark.

See the ``get_warehouse_stock`` docstring and ``WAREHOUSE_ROUTER_SYSTEM_PROMPT`` below for
the finding-by-finding mapping. This is the agent Stage 1 grades as the fix and Stage 2
redeploys to the Lab 7 runtime.
"""

import json
from collections import defaultdict
from pathlib import Path

import yaml
from strands import Agent, tool

from util.odata_tool import odata_caller

# The generic odata_caller is a Strands @tool (a DecoratedFunctionTool). ``.__wrapped__`` is
# the plain underlying function returning a dict, so get_warehouse_stock can reuse it directly
# for auth + response formatting without going through tool-invocation machinery — one code
# path for every SAP OData call, DRY across the deep tool and the dynamic fallback.
_odata_call = odata_caller.__wrapped__

# Directory of OpenAPI specs the selector sub-agent reasons over. Matches Lab 06/07:
# the notebook runs from the repo root, so this relative path resolves to assets/knowledgebase.
KNOWLEDGEBASE_PATH = "./assets/knowledgebase"

# The OData service root for warehouse physical stock. The entity set lives one level
# below this: the agent must call it as the `endpoint`, not append it to the URL.
WAREHOUSE_ODATA_BASE_URL = (
    "https://sandbox.api.sap.com/s4hanacloud/sap/opu/odata4/sap/"
    "api_whse_physstockprod/srvd_a2x/sap/whsephysicalstockproducts/0001"
)

# SAP EWM warehouse number this agent operates over. Encoded once here and reused by the deep
# get_warehouse_stock tool so the $filter is never guessed at runtime.
# TODO: Set to your warehouse number.
WAREHOUSE_ID = "1750"

# TODO: Adjust capacity for your warehouse (used in evaluation scenarios and low-stock judgement).
WAREHOUSE_CAPACITY = 500

# An item counts as "low on stock" when its PER-PRODUCT total on-hand quantity is below this
# fraction of nominal capacity. 0.2 * 500 = 100 units. Encoded here (not left to the model) so
# the low-stock answer is a deterministic threshold applied to aggregated totals, not a vibe.
LOW_STOCK_THRESHOLD_RATIO = 0.2
LOW_STOCK_THRESHOLD = int(WAREHOUSE_CAPACITY * LOW_STOCK_THRESHOLD_RATIO)


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
            except Exception as e:  # noqa: BLE001 malformed spec shouldn't break agent build
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


# --- Baseline warehouse prompt (identical to Lab 06/07) --------------------------------
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

AUTHENTICATION:
Every odata_caller call to the SAP sandbox must authenticate, or it returns 401. Always pass
auth_type="api_key" and auth_env_var="SAP_S4HANA_PUBLIC_CLOUD_KEY", for example:
  odata_caller(base_url="...", endpoint="...", operation="get",
               auth_type="api_key", auth_env_var="SAP_S4HANA_PUBLIC_CLOUD_KEY")

Focus on SAP S/4 HANA OData endpoints, warehouse management APIs, and supply chain operations.

Available tools:
- SelectorAPIAgentAsATool: Picks the right SAP OData API/endpoint for a query from the known OpenAPI specs
- odata_caller: Universal OData tool for SAP API interactions with built-in authentication and query parameter support
"""


def build_warehouse_agent(model, system_prompt=WAREHOUSE_SYSTEM_PROMPT,
                          knowledgebase_path=KNOWLEDGEBASE_PATH):
    """Build the Lab 06 baseline warehouse agent (selector sub-agent + odata_caller).

    This is the two-agent architecture deployed in Lab 07: the agent discovers the schema at
    runtime via the selector and ``$metadata``. Stage 1 grades this as the naive baseline. For
    the eval-driven fix Stage 1 grades and Stage 2 deploys, see ``build_improved_warehouse_agent``.
    """
    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=[_build_selector_tool(model, knowledgebase_path), odata_caller],
    )


# --- Improved architecture: a deep tool + a router that keeps dynamic discovery as fallback --
#
# Stage 1's trajectory judge flagged three wasteful patterns on warehouse-stock queries. Each is
# knowable at design time, so the fix moves it out of the LLM's runtime reasoning and into code:
#
#   Judge finding (Stage 1 baseline)          →  Removed by get_warehouse_stock
#   ---------------------------------------------------------------------------------
#   repeated $metadata schema rediscovery     →  field names compiled into $select
#   trial-and-error $filter guessing          →  $filter built deterministically in Python
#   unnecessary selector LLM round-trip       →  no selector on this path; direct call
#
# The selector + odata_caller stay wired in as a *fallback*, so the improved agent is a router:
# deep tool for the hot path, dynamic discovery for everything else.

# The entity returns one row per storage BIN, so a single product's stock is spread across many
# rows. Answering "what is low on stock?" therefore requires aggregating bin rows to per-product
# totals BEFORE comparing to capacity — otherwise a product with 1,772 units across four bins
# looks "critically low" because one of its bins holds two units. OData v4 $apply/groupby would do
# this server-side, but this SAP sandbox entity rejects it (400), so we sum in Python. All 188
# warehouse rows come back in one page ($top=1000), so the aggregation stays a single round-trip.
_STOCK_ROW_PAGE_SIZE = 1000
_QTY_FIELD = "EWMStockQuantityInBaseUnit"
_UNIT_FIELD = "EWMStockQuantityBaseUnit"


def _extract_rows(odata_result: dict) -> list:
    """Pull the OData ``value`` list back out of _odata_call's formatted text blob.

    _odata_call returns a human-readable string with the raw JSON appended after a
    ``📄 Response:`` marker. For low-stock aggregation we need the structured rows, so we slice
    that JSON back out and parse it. Returns [] if the shape is anything other than success.
    """
    if odata_result.get("status") != "success":
        return []
    text = odata_result.get("content", [{}])[0].get("text", "")
    marker = "📄 Response:"
    idx = text.find(marker)
    if idx == -1:
        return []
    try:
        payload = json.loads(text[idx + len(marker):])
    except json.JSONDecodeError:
        return []
    rows = payload.get("value")
    return rows if isinstance(rows, list) else []


def _summarize_low_stock(rows: list) -> dict:
    """Aggregate bin-level rows to per-product totals and flag which products are low on stock.

    Returns the same ``{status, content:[{text}]}`` shape as _odata_call, but the text is a
    product-total table (ascending by total) with a LOW flag applied against LOW_STOCK_THRESHOLD,
    so the agent reports products — not individual bins — and never calls a full-stock bin the
    whole product's supply.
    """
    totals: dict = defaultdict(float)
    units: dict = {}
    for row in rows:
        product = row.get("Product")
        if not product:
            continue
        try:
            totals[product] += float(row.get(_QTY_FIELD) or 0)
        except (TypeError, ValueError):
            continue
        units.setdefault(product, row.get(_UNIT_FIELD) or "")

    lines = [
        f"Per-product stock totals for Warehouse {WAREHOUSE_ID} "
        f"(low-stock threshold: < {LOW_STOCK_THRESHOLD} units, "
        f"{int(LOW_STOCK_THRESHOLD_RATIO * 100)}% of {WAREHOUSE_CAPACITY} nominal capacity).",
        "Totals are summed across all storage bins per product.",
        "",
    ]
    low = []
    for product in sorted(totals, key=totals.get):
        total = totals[product]
        is_low = total < LOW_STOCK_THRESHOLD
        flag = "LOW" if is_low else "ok"
        lines.append(f"  {product}: {total:.0f} {units.get(product, '')} [{flag}]")
        if is_low:
            low.append(product)

    lines.append("")
    lines.append(
        f"Low on stock ({len(low)}): {', '.join(low)}" if low
        else "No products are below the low-stock threshold."
    )
    return {"status": "success", "content": [{"text": "\n".join(lines)}]}


@tool
def get_warehouse_stock(product: str = "", low_stock_only: bool = False) -> dict:
    """Get real-time physical stock for GlobalTech's Distribution Center (Warehouse 1750).

    This is the improved, eval-driven replacement for the baseline's selector + $metadata +
    hand-built $filter loop. The SAP service root, entity set, field names, warehouse ID, and
    server-side query construction are all encoded here, so answering a warehouse-stock question
    takes exactly ONE OData call — no schema rediscovery, no filter guessing, no selector.

    Use this for any question about how much of a product is on hand in the warehouse: single
    product, full overview, or which items are low. For anything OUTSIDE warehouse physical
    stock, fall back to SelectorAPIAgentAsATool + odata_caller instead.

    Args:
        product: A product code such as "WM-AN02" to query one product. Leave empty ("") to
            return all products in the warehouse.
        low_stock_only: When True, return a per-PRODUCT total-stock table (summed across bins)
            with each product flagged low/ok against the reorder threshold, so "what is low on
            stock?" is answered correctly in one call — not distorted by per-bin fragments.

    Returns:
        Dict with ``status`` and ``content`` — the same shape as ``odata_caller``. For a normal
        query, the matching WarehousePhysicalStockProducts rows (Product, on-hand quantity, unit,
        bin). For ``low_stock_only=True``, a per-product total-stock table with low-stock flags.
    """
    # $filter: always scope to this warehouse; add the product only when one was requested.
    # Built in code, so the model never guesses a filter and never sees a 400-driven retry.
    filter_clause = f"EWMWarehouse eq '{WAREHOUSE_ID}'"
    if product:
        filter_clause = f"Product eq '{product}' and " + filter_clause

    odata_params = {
        "$filter": filter_clause,
        # The exact field names the baseline kept rediscovering via $metadata, fixed here.
        "$select": f"Product,{_QTY_FIELD},{_UNIT_FIELD},EWMStorageBin",
    }
    # Low-stock questions need PRODUCT totals, but the entity is bin-level. Pull the whole
    # warehouse in one page so we can aggregate deterministically below.
    if low_stock_only:
        odata_params["$top"] = str(_STOCK_ROW_PAGE_SIZE)

    result = _odata_call(
        base_url=WAREHOUSE_ODATA_BASE_URL,
        endpoint="WarehousePhysicalStockProducts",
        operation="get",
        odata_params=odata_params,
        auth_type="api_key",
        auth_env_var="SAP_S4HANA_PUBLIC_CLOUD_KEY",
    )

    # Aggregate bin rows to per-product totals and apply the reorder threshold in code, so the
    # low-stock verdict is deterministic and correct rather than eyeballed from raw bin rows.
    if low_stock_only and result.get("status") == "success":
        return _summarize_low_stock(_extract_rows(result))

    return result


# Router prompt for the improved agent. It is deliberately NOT the baseline prompt plus a schema
# dump (that was the earlier prompt-only patch). Instead it routes: the deep tool owns the
# warehouse-stock hot path, the selector + odata_caller remain for open-ended discovery.
WAREHOUSE_ROUTER_SYSTEM_PROMPT = """
You are an expert Warehouse Operations Manager for GlobalTech Manufacturing's Distribution Center (Warehouse 1750).
You have real-time access to SAP warehouse data through the tools below.

TOOL ROUTING (choose the right tool first, do not explore blindly):
- For any question about physical stock in the warehouse — how much of a product is on hand, a
  full inventory overview, or which items are low on stock — call get_warehouse_stock. It already
  knows the API, schema, and warehouse, and answers in a single call. Pass a product code (e.g.
  "WM-AN02") for one product, leave it empty for all products, and set low_stock_only=True for
  low-stock questions.
- ONLY for questions outside warehouse physical stock (other SAP domains, unfamiliar entities)
  fall back to dynamic discovery: use SelectorAPIAgentAsATool to pick the API, then odata_caller.
  Do not use this path for plain stock questions — get_warehouse_stock is faster and correct.

PRODUCT KNOWLEDGE:
- WM-AN01: Advanced Sensors (high-precision electronic components)
- WM-AN02: Control Units (critical automation hardware)
- WM-AN03: Power Modules (electrical power management systems)
- WM-AN04: Communication Devices (networking and connectivity hardware)

LOW-STOCK JUDGEMENT:
- Each product has a nominal capacity of {capacity} units; an item is "low on stock" when its
  total on-hand quantity is under {threshold} units (20% of capacity). Call get_warehouse_stock
  with low_stock_only=True — it returns PER-PRODUCT totals (summed across all storage bins) with
  each product already flagged low/ok. Report the flagged products with their totals; never treat
  a single low-quantity storage bin as the whole product's stock.

COMMUNICATION STYLE:
- Be professional but conversational and succinct.
- Provide specific, actionable insights with quantitative data from the tool results.
- If you know the user's preferences from memory, apply them without asking.
- Do not use emojis.

When users ask questions:
1. Pick the right tool per the routing rules above.
2. Read the returned rows and answer with the specific quantities.
3. For fulfillment questions, compare the on-hand quantity against the requested amount and give a
   clear yes/no with the numbers.
""".format(capacity=WAREHOUSE_CAPACITY, threshold=LOW_STOCK_THRESHOLD)


def _build_selector_tool(model, knowledgebase_path=KNOWLEDGEBASE_PATH):
    """Wire the selector sub-agent up as a Strands tool (shared by both architectures)."""
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

    return SelectorAPIAgentAsATool


def build_improved_warehouse_agent(model, knowledgebase_path=KNOWLEDGEBASE_PATH):
    """Build the improved, eval-driven warehouse agent (deep tool + dynamic-discovery fallback).

    This is the fix Stage 1 grades and Stage 2 redeploys. It routes warehouse-stock questions to
    the deterministic ``get_warehouse_stock`` tool (one call, no rediscovery) while keeping the
    Lab 06 selector + ``odata_caller`` available for anything off the hot path. The before→after
    story is architectural, not a prompt tweak: ``odata_caller`` × N → ``get_warehouse_stock`` × 1.
    """
    return Agent(
        model=model,
        system_prompt=WAREHOUSE_ROUTER_SYSTEM_PROMPT,
        tools=[
            get_warehouse_stock,
            _build_selector_tool(model, knowledgebase_path),
            odata_caller,
        ],
    )
