import json
import os
from dotenv import load_dotenv

from agent.graph import app

load_dotenv()

if not os.environ.get("GROQ_API_KEY"):
    print("Warning: GROQ_API_KEY is not set. Please set it in .env file.")

with open("data/mock_logs.json", "r") as f:
    MOCK_DATA = json.load(f)

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

console = Console()

def run_test():
    run_all = os.environ.get("RUN_ALL", "false").lower() == "true"
    
    for incident in MOCK_DATA:
        console.rule(f"[bold blue]Processing {incident['incident_id']}: {incident['description']}[/bold blue]")
        
        # Pre-process logs to inject event_ids
        processed_logs = []
        for i, log in enumerate(incident["raw_logs"]):
            log_copy = dict(log)
            log_copy["event_id"] = f"{incident['incident_id']}-E{i+1:03d}"
            processed_logs.append(log_copy)
            
        initial_state = {
            "incident_id": incident["incident_id"],
            "raw_logs": processed_logs, 
            "messages": [],
            "iteration_count": 0,
            "mitre_techniques": [],
            "candidate_evidence": [],
            "detected_signals": [],
            "search_history": [],
            "tool_results": [],
            "errors": []
        }
        
        try:
            # Invoke LangGraph app
            final_state = app.invoke(initial_state)
            
            console.print("\n[bold cyan]--- FINAL STATE ---[/bold cyan]")
            console.print(f"[bold]Verdict:[/bold] {final_state.get('triage_verdict')}")
            console.print(f"[bold]Incident Type:[/bold] {final_state.get('incident_type')}")
            console.print(f"[bold]Severity:[/bold] {final_state.get('severity')}")
            console.print(f"[bold]Iterations:[/bold] {final_state.get('iteration_count')}")
            console.print(f"[bold]Tool Executions:[/bold] {len(final_state.get('tool_results', []))}")
            
            if final_state.get('final_report'):
                console.print("\n")
                console.print(Panel(Markdown(final_state['final_report']), title="[bold green]GENERATED REPORT[/bold green]", border_style="green"))
            else:
                console.print("\n[yellow](No report generated)[/yellow]")
        except Exception as e:
            console.print(f"\n[bold red][ERROR] An error occurred while processing {incident['incident_id']}: {e}[/bold red]")
            import traceback
            traceback.print_exc()
            
            
        if not run_all:
            print("\n[INFO] Breaking early after 1 incident. Set RUN_ALL=true in .env to run all.")
            break
        else:
            import time
            time.sleep(4)

if __name__ == "__main__":
    run_test()
