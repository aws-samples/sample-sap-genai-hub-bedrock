from typing import Dict, List, Any
import json


def trace_agent_execution_path(agent, detailed=True, show_tool_results=True):
    """
    Trace and visualize the execution path of a Strands agent, including sub-agents,
    tools used, messages exchanged, and performance metrics.

    Args:
        agent: The Strands Agent instance to trace
        detailed: If True, shows full message content; if False, shows summaries
        show_tool_results: If True, includes tool execution results

    Returns:
        Dict containing structured trace information
    """

    trace_data = {
        "total_messages": len(agent.messages),
        "conversation_turns": [],
        "tools_used": [],
        "sub_agents_invoked": [],
        "summary": {},
    }

    tool_count = 0
    sub_agent_count = 0
    turn_number = 0

    print("=" * 80)
    print(" AGENT EXECUTION PATH TRACE")
    print("=" * 80)
    print(f"\nTotal Messages in Conversation: {len(agent.messages)}\n")

    i = 0
    while i < len(agent.messages):
        msg = agent.messages[i]
        role = msg.get("role", "unknown")
        content = msg.get("content", [])

        if role == "user":
            turn_number += 1
            turn_data = {
                "turn": turn_number,
                "user_message": "",
                "agent_response": "",
                "tools_in_turn": [],
                "sub_agents_in_turn": [],
            }

            # Extract user message
            for item in content:
                if "text" in item:
                    user_text = item["text"]
                    turn_data["user_message"] = user_text
                    print(f"\n{'─'*80}")
                    print(f" TURN {turn_number}: USER QUERY")
                    print(f"{'─'*80}")
                    if detailed:
                        print(f"{user_text}")
                    else:
                        print(
                            f"{user_text[:150]}..."
                            if len(user_text) > 150
                            else user_text
                        )
                elif "toolResult" in item:
                    # This is a tool result from previous turn
                    tool_result = item["toolResult"]
                    tool_use_id = tool_result.get("toolUseId", "unknown")
                    status = tool_result.get("status", "unknown")
                    result_content = tool_result.get("content", [])

                    if show_tool_results:
                        print(
                            f"\n  ↳ Tool Result (ID: {tool_use_id[-8:]}): {status.upper()}"
                        )
                        for res_item in result_content:
                            if "text" in res_item:
                                result_text = res_item["text"]
                                if detailed:
                                    print(
                                        f"     {result_text[:500]}..."
                                        if len(result_text) > 500
                                        else f"     {result_text}"
                                    )
                                else:
                                    print(
                                        f"     {result_text[:150]}..."
                                        if len(result_text) > 150
                                        else f"     {result_text}"
                                    )

            # Look ahead for assistant response
            if (
                i + 1 < len(agent.messages)
                and agent.messages[i + 1].get("role") == "assistant"
            ):
                i += 1
                assistant_msg = agent.messages[i]
                assistant_content = assistant_msg.get("content", [])

                print(f"\n AGENT RESPONSE:")
                print(f"{'─'*80}")

                for item in assistant_content:
                    if "text" in item:
                        response_text = item["text"]
                        turn_data["agent_response"] = response_text
                        if detailed:
                            print(f"{response_text}")
                        else:
                            print(
                                f"{response_text[:200]}..."
                                if len(response_text) > 200
                                else response_text
                            )

                    elif "toolUse" in item:
                        tool_count += 1
                        tool_use = item["toolUse"]
                        tool_name = tool_use.get("name", "unknown")
                        tool_use_id = tool_use.get("toolUseId", "unknown")
                        tool_input = tool_use.get("input", {})

                        tool_info = {
                            "tool_number": tool_count,
                            "tool_name": tool_name,
                            "tool_use_id": tool_use_id,
                            "input": tool_input,
                        }

                        turn_data["tools_in_turn"].append(tool_info)
                        trace_data["tools_used"].append(tool_info)

                        # Check if this is a sub-agent call
                        if "Agent" in tool_name or "agent" in tool_name.lower():
                            sub_agent_count += 1
                            sub_agent_info = {
                                "sub_agent_number": sub_agent_count,
                                "sub_agent_name": tool_name,
                                "query": tool_input.get("query", "N/A"),
                            }
                            turn_data["sub_agents_in_turn"].append(sub_agent_info)
                            trace_data["sub_agents_invoked"].append(sub_agent_info)

                        print(f"\n  🔧 Tool #{tool_count}: {tool_name}")
                        print(f"     ID: {tool_use_id[-12:]}")

                        if "Agent" in tool_name or "agent" in tool_name.lower():
                            print(f"     ⚡ SUB-AGENT INVOCATION #{sub_agent_count}")
                            if "query" in tool_input:
                                query_text = tool_input["query"]
                                print(
                                    f"     Query: {query_text[:100]}..."
                                    if len(query_text) > 100
                                    else f"     Query: {query_text}"
                                )

                        if detailed and tool_input:
                            print(f"     Input Parameters:")
                            for key, value in tool_input.items():
                                # if isinstance(value, str) and len(value) > 100:
                                # print(f"       - {key}: {value[:100]}...")
                                # else:
                                print(f"       - {key}: {value}")

            trace_data["conversation_turns"].append(turn_data)

        i += 1

    # Generate summary
    trace_data["summary"] = {
        "total_turns": turn_number,
        "total_tools_used": tool_count,
        "total_sub_agents_invoked": sub_agent_count,
        "unique_tools": list(set([t["tool_name"] for t in trace_data["tools_used"]])),
        "unique_sub_agents": list(
            set([s["sub_agent_name"] for s in trace_data["sub_agents_invoked"]])
        ),
    }

    print(f"\n\n{'='*80}")
    print(" EXECUTION SUMMARY")
    print(f"{'='*80}")
    print(f"\n Total Conversation Turns: {turn_number}")
    print(f"🔧 Total Tools Used: {tool_count}")
    print(f"⚡ Total Sub-Agent Invocations: {sub_agent_count}")
    print(f"\n Unique Tools: {', '.join(trace_data['summary']['unique_tools'])}")
    if trace_data["summary"]["unique_sub_agents"]:
        print(
            f" Unique Sub-Agents: {', '.join(trace_data['summary']['unique_sub_agents'])}"
        )

    return trace_data


def export_trace_to_json(trace_data, filename="agent_trace.json"):
    """
    Export the trace data to a JSON file for further analysis.

    Args:
        trace_data: The trace data dictionary from trace_agent_execution_path
        filename: Output filename for the JSON file
    """
    with open(filename, "w") as f:
        json.dump(trace_data, f, indent=2)
    print(f"\n Trace data exported to: {filename}")


def get_tool_usage_stats(trace_data):
    """
    Analyze tool usage patterns from trace data.

    Args:
        trace_data: The trace data dictionary from trace_agent_execution_path

    Returns:
        Dict with tool usage statistics
    """
    tool_usage = {}
    for tool in trace_data["tools_used"]:
        tool_name = tool["tool_name"]
        tool_usage[tool_name] = tool_usage.get(tool_name, 0) + 1

    print("\nTOOL USAGE STATISTICS")
    print("=" * 80)
    for tool_name, count in sorted(
        tool_usage.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"  {tool_name}: {count} time(s)")

    return tool_usage


# Display Agent Performance Metrics
def display_agent_metrics(response):
    """
    Parse and display agent response metrics in a clean, readable format.

    Args:
        response: Agent response object containing metrics
    """
    if hasattr(response, "metrics") and response.metrics:
        metrics = response.metrics

        # Token Usage from accumulated_usage
        if hasattr(metrics, "accumulated_usage"):
            usage = metrics.accumulated_usage
            print("\n Accumulated Token Usage:")
            print(f"  • Input Tokens:  {usage.get('inputTokens', 'N/A'):,}")
            print(f"  • Output Tokens: {usage.get('outputTokens', 'N/A'):,}")
            print(f"  • Total Tokens:  {usage.get('totalTokens', 'N/A'):,}")

        # Accumulated Metrics
        if hasattr(metrics, "accumulated_metrics"):
            acc_metrics = metrics.accumulated_metrics
            print("\n️  Performance:")
            latency_ms = acc_metrics.get("latencyMs", 0)
            latency_sec = latency_ms / 1000
            print(
                f"  • Accumulated Latency: {latency_ms:,} ms ({latency_sec:.2f} seconds)"
            )

    else:
        print("\n⚠  No metrics available for this response")
