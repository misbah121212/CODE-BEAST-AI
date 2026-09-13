from langgraph.graph import StateGraph, END
from app.agents.state import AgentState
from app.agents.nodes import (
    security_agent_node,
    architecture_agent_node,
    performance_agent_node,
    testing_agent_node,
    database_agent_node,
    similarity_agent_node,
    dx_agent_node,
    finops_agent_node,
    nararouter_supervisor_node
)

def create_orchestrator_graph():
    """
    Creates and compiles the LangGraph that runs the specialized agents in a strict, 
    sequential step-by-step pipeline from Card 01 to Card 10.
    """
    workflow = StateGraph(AgentState)
    
    async def dispatcher_node(state: AgentState):
        print("Starting step-by-step sequential multi-agent analysis topology...", flush=True)
        return state
        
    # Add nodes in topology order
    workflow.add_node("dispatcher", dispatcher_node)
    workflow.add_node("security_agent", security_agent_node)
    workflow.add_node("architecture_agent", architecture_agent_node)
    workflow.add_node("performance_agent", performance_agent_node)
    workflow.add_node("testing_agent", testing_agent_node)
    workflow.add_node("database_agent", database_agent_node)
    workflow.add_node("similarity_agent", similarity_agent_node)
    workflow.add_node("dx_agent", dx_agent_node)
    workflow.add_node("finops_agent", finops_agent_node)
    workflow.add_node("nararouter_supervisor", nararouter_supervisor_node)
    
    # Define STRICT SEQUENTIAL edges (01 -> 02 -> 03 -> 04 -> 05 -> 06 -> 07 -> 08 -> 09 -> 10)
    workflow.set_entry_point("dispatcher")
    workflow.add_edge("dispatcher", "security_agent")
    workflow.add_edge("security_agent", "architecture_agent")
    workflow.add_edge("architecture_agent", "performance_agent")
    workflow.add_edge("performance_agent", "testing_agent")
    workflow.add_edge("testing_agent", "database_agent")
    workflow.add_edge("database_agent", "similarity_agent")
    workflow.add_edge("similarity_agent", "dx_agent")
    workflow.add_edge("dx_agent", "finops_agent")
    workflow.add_edge("finops_agent", "nararouter_supervisor")
    workflow.add_edge("nararouter_supervisor", END)
    
    graph = workflow.compile()
    return graph
