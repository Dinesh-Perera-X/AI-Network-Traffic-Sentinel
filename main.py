import argparse
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.flow_parser import FlowParser
from analyzers.scan_detector import ScanDetector
from analyzers.anomaly_detector import AnomalyDetector
from actions.quarantine import QuarantineGenerator
from exporters.siem_exporter import SIEMExporter

console = Console()

def display_banner():
    banner = (
        "[bold cyan]AI-Network-Traffic-Sentinel 🌐🔍[/bold cyan]\n"
        "[dim]Project 2 Complete: Threat Detection & SIEM Exporter[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="AI Network Traffic & Flow Log Monitor.")
    parser.add_argument("--logs", help="Path to VPC flow logs JSON", default="data/vpc_flow_logs.json")
    parser.add_argument("--export", help="Export SIEM alerts to JSON", action="store_true")
    args = parser.parse_args()

    display_banner()

    console.print("[yellow]⚡ Initializing Real-Time Terminal Traffic Feed...[/yellow]")
    time.sleep(0.5)

    flows = FlowParser.load_flows(args.logs)
    scanned = ScanDetector.evaluate_flows(flows)
    anomalies = AnomalyDetector.evaluate_traffic_anomalies(scanned)
    secured = QuarantineGenerator.process_quarantine_actions(anomalies)

    table = Table(title="[bold green]🚀 Project 2: Final Security & SIEM Pipeline Dashboard[/bold green]", border_style="green")
    table.add_column("Flow ID", justify="center", style="dim")
    table.add_column("Source IP", style="yellow")
    table.add_column("Port", justify="center", style="magenta")
    table.add_column("Threat Level", justify="center")
    table.add_column("Action Taken", justify="center", style="bold")

    for f in secured:
        level = f["threat_level"]
        level_str = "[bold red]CRITICAL[/bold red]" if level == "CRITICAL" else "[bold yellow]HIGH[/bold yellow]" if level == "HIGH" else "[bold green]NORMAL[/bold green]"
        action = f["quarantine_action"]
        action_str = f"[bold red]{action}[/bold red]" if action == "BLOCK & ISOLATE" else f"[bold yellow]{action}[/bold yellow]" if action == "FLAG FOR REVIEW" else f"[green]{action}[/green]"

        table.add_row(
            f["flow_id"],
            f["source_ip"],
            str(f["destination_port"]),
            level_str,
            action_str
        )

    console.print(table)

    alert_count = SIEMExporter.export_alerts(secured)
    console.print(f"\n[bold green]✔ Day 5 Complete:[/bold green] Exported [bold cyan]{alert_count}[/bold cyan] security alerts to [bold cyan]data/siem_alerts.json[/bold cyan].")

if __name__ == "__main__":
    main()
