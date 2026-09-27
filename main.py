import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.flow_parser import FlowParser
from analyzers.scan_detector import ScanDetector
from analyzers.anomaly_detector import AnomalyDetector
from actions.quarantine import QuarantineGenerator

console = Console()

def display_banner():
    banner = (
        "[bold cyan]AI-Network-Traffic-Sentinel 🌐🔍[/bold cyan]\n"
        "[dim]Lesson 2: Network Security & AI-Powered Monitoring Engine[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="AI Network Traffic & Flow Log Monitor.")
    parser.add_argument("--logs", help="Path to VPC flow logs JSON", default="data/vpc_flow_logs.json")
    args = parser.parse_args()

    display_banner()

    flows = FlowParser.load_flows(args.logs)
    scanned = ScanDetector.evaluate_flows(flows)
    anomalies = AnomalyDetector.evaluate_traffic_anomalies(scanned)
    secured_flows = QuarantineGenerator.process_quarantine_actions(anomalies)

    table = Table(title="[bold red]🛡️ Day 4: Automated IP Quarantine & Security Actions[/bold red]", border_style="red")
    table.add_column("Flow ID", justify="center", style="dim")
    table.add_column("Source IP", style="yellow")
    table.add_column("Threat Level", justify="center")
    table.add_column("Anomaly?", justify="center")
    table.add_column("Action Taken", justify="center", style="bold")

    if not secured_flows:
        table.add_row("-", "No flows found.", "-", "-", "-")
    else:
        for f in secured_flows:
            level = f["threat_level"]
            level_str = "[bold red]CRITICAL[/bold red]" if level == "CRITICAL" else "[bold yellow]HIGH[/bold yellow]" if level == "HIGH" else "[bold green]NORMAL[/bold green]"
            
            anomaly_str = "[red]Yes[/red]" if f["statistical_anomaly"] else "[dim]No[/dim]"
            
            action = f["quarantine_action"]
            action_str = f"[bold red]{action}[/bold red]" if action == "BLOCK & ISOLATE" else f"[bold yellow]{action}[/bold yellow]" if action == "FLAG FOR REVIEW" else f"[green]{action}[/green]"

            table.add_row(
                f["flow_id"],
                f["source_ip"],
                level_str,
                anomaly_str,
                action_str
            )

    console.print(table)
    console.print(f"\n[bold green]✔ Day 4 Complete:[/bold green] Evaluated automated security responses for [bold cyan]{len(secured_flows)}[/bold cyan] flows.")

if __name__ == "__main__":
    main()
