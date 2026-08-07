"""Deploy the improved warehouse agent to AgentCore Runtime for Lab 09 Stage 2.

Stage 2 verifies the Stage-1 fix in production, which first requires shipping that
fix to the Lab 7 runtime. That redeploy is pure AgentCore plumbing (write the entrypoint
and requirements, configure the Runtime, patch the generated Dockerfile, launch, wait for
READY) and not the focus of an evaluation lab, so it lives here instead of the notebook.

The deployed entrypoint imports ``build_improved_warehouse_agent`` from ``util.warehouse_agent``
(the Dockerfile copies ``util/`` into the container), so the agent graded in production is the
exact same eval-driven architecture Stage 1 grades locally — the ``get_warehouse_stock`` deep tool
plus the selector/``odata_caller`` fallback — true parity, no duplicated code.
"""

from __future__ import annotations

import json
import os

# Entrypoint written into the build context and run inside the AgentCore container. It stays
# tiny on purpose: the agent, prompts, and tools all come from util/, which the Dockerfile copies in.
ENTRYPOINT_SOURCE = '''\
# Lab 09 Stage 2 entrypoint: the improved warehouse agent, redeployed to verify the fix in prod.
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import RequestContext

from util.strands_bedrock_sap_genai_hub import SAPGenAIHubModel
from util.warehouse_agent import build_improved_warehouse_agent

app = BedrockAgentCoreApp()
model = SAPGenAIHubModel(model_id="{model_id}")


@app.entrypoint
def warehouse_agent_entrypoint(payload, context: RequestContext):
    """Invoke the improved warehouse agent (deep tool + dynamic-discovery fallback)."""
    user_input = payload.get("prompt")
    print("User input:", user_input)
    agent = build_improved_warehouse_agent(model)
    return agent(user_input).message


if __name__ == "__main__":
    app.run()
'''

# Container dependencies. Versions are pinned to mirror pyproject.toml, NOT loosened, so the
# deployed runtime resolves the same stack the notebook was validated against. In particular
# sap-ai-sdk-gen is pinned >=6.10.0: the 5.x line caps botocore below the floor that a modern
# bedrock-agentcore needs (see the pyproject.toml comment), so an unbounded >=5.5.0 here would
# let the container resolve the exact combination pyproject was written to avoid. The starter
# toolkit auto-adds aws-opentelemetry-distro and the opentelemetry-instrument entrypoint when
# observability is enabled (the default), so OTEL spans — which Stage 2 grades — need no line here.
REQUIREMENTS = """\
# AgentCore requirements (pins mirror pyproject.toml)
strands-agents==1.14.0
strands-agents-tools==0.2.0
uv
boto3>=1.37.0
bedrock-agentcore>=1.6.0
bedrock-agentcore-starter-toolkit==0.1.14
# SAP GenAI Hub and warehouse agent dependencies
sap-ai-sdk-gen[all]>=6.10.0
pyyaml
requests
python-dotenv
"""

# Lines inserted into the generated Dockerfile (before CMD) so the container has the util
# package, the OpenAPI knowledgebase, and the SAP GenAI Hub credentials.
_DOCKERFILE_ADDITIONS = [
    "",
    "# Copy util directory (required for SAP GenAI Hub model and OData tool)",
    "COPY util/ ./util/",
    "",
    "# Copy assets directory (required for OpenAPI knowledgebase)",
    "COPY assets/ ./assets/",
    "",
    "# Copy the config.json from your local machine",
    "COPY config.json /app/.aicore/config.json",
    "",
    "# Set AICORE_HOME environment variable for SAP GenAI Hub SDK",
    "ENV AICORE_HOME=/app/.aicore",
    "",
]

END_STATUSES = ["READY", "CREATE_FAILED", "DELETE_FAILED", "UPDATE_FAILED"]


def _write_build_context(entrypoint_file, model_id):
    """Write the entrypoint, requirements.txt, and config.json into the build context."""
    with open(entrypoint_file, "w") as f:
        f.write(ENTRYPOINT_SOURCE.format(model_id=model_id))

    with open("requirements.txt", "w") as f:
        f.write(REQUIREMENTS)

    # Materialize ~/.aicore/config.json into the build context so the Dockerfile can COPY it.
    # This file is gitignored and transient, so it may be absent when Lab 09 runs on its own.
    config_path = os.path.expanduser("~/.aicore/config.json")
    if not os.path.exists(config_path):
        raise SystemExit(
            f"{config_path} not found. Run notebook 00 to configure SAP AI Core credentials first."
        )
    with open(config_path, "r") as src:
        aicore_config = json.load(src)
    with open("config.json", "w") as f:
        json.dump(aicore_config, f, indent=2)


def _patch_dockerfile(dockerfile="Dockerfile"):
    """Insert the util/, assets/, and SAP GenAI Hub credential lines before CMD (idempotent)."""
    with open(dockerfile, "r") as f:
        content = f.read()

    if "AICORE_HOME" in content:
        return "Dockerfile already contains SAP GenAI Hub configuration, skipping."

    lines = content.split("\n")
    cmd_index = next((i for i, line in enumerate(lines) if line.strip().startswith("CMD")), -1)
    if cmd_index == -1:
        raise SystemExit("Could not find CMD instruction in the generated Dockerfile.")

    modified = lines[:cmd_index] + _DOCKERFILE_ADDITIONS + lines[cmd_index:]
    with open(dockerfile, "w") as f:
        f.write("\n".join(modified))
    return "Dockerfile modified with util/, assets/, and SAP GenAI Hub configuration."


def deploy_improved_agent(
    agent_name,
    region,
    sap_api_key,
    entrypoint_file="warehouse_agent_agentcore.py",
    model_id="anthropic--claude-4.5-sonnet",
    poll_seconds=10,
):
    """Redeploy the improved warehouse agent in-place to the Lab 7 AgentCore Runtime.

    Reuses ``agent_name`` with ``auto_update_on_conflict=True`` so the existing AGENT_ID /
    AGENT_ARN stay valid. Blocks until the runtime reaches READY and raises ``SystemExit`` on
    any failure status, so the caller never grades a half-deployed (still-baseline) runtime.

    Args:
        agent_name: The Lab 7 runtime name to update in place.
        region: AWS region of the runtime.
        sap_api_key: SAP S/4HANA key passed to the container so its OData calls authenticate.
        entrypoint_file: Path for the generated entrypoint (matches the Lab 7 filename).
        model_id: SAP GenAI Hub model the deployed agent uses.
        poll_seconds: Seconds between runtime status polls.

    Returns:
        The final runtime status string ("READY").
    """
    import time

    from bedrock_agentcore_starter_toolkit import Runtime

    _write_build_context(entrypoint_file, model_id)
    print("Wrote entrypoint, requirements.txt, and config.json into the build context.")

    runtime = Runtime()
    print(f"Updating existing AgentCore Runtime: {agent_name}")
    runtime.configure(
        entrypoint=entrypoint_file,
        auto_create_execution_role=True,
        auto_create_ecr=True,
        requirements_file="requirements.txt",
        region=region,
        agent_name=agent_name,
    )
    print(_patch_dockerfile())

    runtime.launch(
        auto_update_on_conflict=True,
        env_vars={"SAP_S4HANA_PUBLIC_CLOUD_KEY": sap_api_key},
    )
    print("Deployment of the improved agent initiated on the existing runtime.")

    status = runtime.status().endpoint["status"]
    print(f"Initial status: {status}")
    while status not in END_STATUSES:
        time.sleep(poll_seconds)
        status = runtime.status().endpoint["status"]
        print(status)

    print(f"\nFinal status: {status}")
    if status != "READY":
        raise SystemExit(
            f"Redeploy did not reach READY (final status: {status}). Stage 2 aborted, "
            "refusing to grade a half-deployed runtime."
        )
    return status
