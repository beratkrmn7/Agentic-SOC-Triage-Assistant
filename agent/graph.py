
from langgraph.graph import StateGraph, END

from agent.models import IncidentState
from agent.nodes import (
    entity_extraction_node,
    automated_detection_node,
    triage_node, 
    evidence_validation_node,
    action_recommendation_node,
    reporter_node
)



# Build Graph
workflow = StateGraph(IncidentState)

# Add nodes
workflow.add_node("entity_extraction_node", entity_extraction_node)
workflow.add_node("automated_detection_node", automated_detection_node)
workflow.add_node("triage_node", triage_node)
workflow.add_node("evidence_validation_node", evidence_validation_node)
workflow.add_node("action_recommendation_node", action_recommendation_node)
workflow.add_node("reporter_node", reporter_node)

# Set entry point
workflow.set_entry_point("entity_extraction_node")

# Edges
workflow.add_edge("entity_extraction_node", "automated_detection_node")
workflow.add_edge("automated_detection_node", "triage_node")
workflow.add_edge("triage_node", "evidence_validation_node")
workflow.add_edge("evidence_validation_node", "action_recommendation_node")
workflow.add_edge("action_recommendation_node", "reporter_node")
workflow.add_edge("reporter_node", END)

# Compile graph
app = workflow.compile()

