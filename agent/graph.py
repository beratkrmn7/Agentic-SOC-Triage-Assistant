import json
import datetime
import ast
from typing import Any

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from agent.models import IncidentState
from agent.tools import tools_list
from agent.nodes import (
    entity_extraction_node,
    automated_detection_node,
    triage_node, 
    process_result_node, 
    evidence_validation_node,
    action_recommendation_node,
    reporter_node, 
    route_triage, 
    route_after_process
)

class CustomToolNode(ToolNode):
    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        input_val = input
        tool_calls_map = {}
        if isinstance(input_val, dict) and "messages" in input_val:
            last_msg = input_val["messages"][-1]
            if hasattr(last_msg, "tool_calls"):
                for tc in last_msg.tool_calls:
                    tool_calls_map[tc["id"]] = tc["args"]
                    
        result = super().invoke(input_val, config, **kwargs)
        
        tool_results = []
        search_history = []
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "name"):
                    timestamp = datetime.datetime.now().isoformat()
                    content_str = msg.content
                    matched_ids = []
                    
                    # Extract query from the original tool call arguments securely
                    query_str = None
                    if hasattr(msg, "tool_call_id") and msg.tool_call_id in tool_calls_map:
                        tc_args = tool_calls_map[msg.tool_call_id]
                        if "query" in tc_args:
                            query_str = tc_args["query"]
                    
                    try:
                        content_dict = ast.literal_eval(content_str)
                        if isinstance(content_dict, dict):
                            if "matched_event_ids" in content_dict:
                                matched_ids = content_dict["matched_event_ids"]
                            if not query_str and "query" in content_dict:
                                query_str = content_dict["query"]
                    except Exception:
                        try:
                            content_json = json.loads(content_str)
                            if "matched_event_ids" in content_json:
                                matched_ids = content_json["matched_event_ids"]
                            if not query_str and "query" in content_json:
                                query_str = content_json["query"]
                        except Exception:
                            pass
                            
                    tool_record = {
                        "tool_name": msg.name,
                        "timestamp": timestamp,
                        "result_summary": content_str[:200] + "..." if len(content_str) > 200 else content_str,
                        "matched_event_ids": matched_ids
                    }
                    
                    if query_str:
                        tool_record["query"] = query_str
                        
                    tool_results.append(tool_record)
                    
                    if msg.name == "search_logs":
                        search_history.append(tool_record)
                        
        return {"messages": result["messages"], "tool_results": tool_results, "search_history": search_history}

# Build Graph
workflow = StateGraph(IncidentState)

# Add nodes
workflow.add_node("entity_extraction_node", entity_extraction_node)
workflow.add_node("automated_detection_node", automated_detection_node)
workflow.add_node("triage_node", triage_node)
workflow.add_node("tools", CustomToolNode(tools_list))
workflow.add_node("process_result", process_result_node)
workflow.add_node("evidence_validation_node", evidence_validation_node)
workflow.add_node("action_recommendation_node", action_recommendation_node)
workflow.add_node("reporter_node", reporter_node)

# Set entry point
workflow.set_entry_point("entity_extraction_node")

# Edges
workflow.add_edge("entity_extraction_node", "automated_detection_node")
workflow.add_edge("automated_detection_node", "triage_node")

workflow.add_conditional_edges(
    "triage_node",
    route_triage,
    {
        "tools": "tools",
        "process_result": "process_result"
    }
)

workflow.add_edge("tools", "triage_node")

workflow.add_conditional_edges(
    "process_result",
    route_after_process,
    {
        "evidence_validation_node": "evidence_validation_node"
    }
)

workflow.add_edge("evidence_validation_node", "action_recommendation_node")
workflow.add_edge("action_recommendation_node", "reporter_node")
workflow.add_edge("reporter_node", END)

# Compile graph
app = workflow.compile()
