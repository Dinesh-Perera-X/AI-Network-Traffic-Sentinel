import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.flow_parser import FlowParser
from analyzers.scan_detector import ScanDetector
from analyzers.anomaly_detector import AnomalyDetector

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
    scanned_flows = ScanDetector.evaluate_flows(flows)
    analyzed_flows = AnomalyDetector.evaluate_traffic_anomalies(scanned_flows)

    table = Table(title="[bold magenta]📈 Day 3: Heuristic Scans & Statistical Volume Anomalies[/bold magenta]", border_style="magenta")
    table.add_column("Flow ID", justify="center", style="dim")
    table.add_column("Source IP", style="yellow")
    table.add_column("Bytes", justify="right", style="cyan")
    table.add_column("Threat Level", justify="center")
    table.add_column("Volume Anomaly?", justify="center")

    if not analyzed_flows:
        table.add_row("-", "No flows found.", "-", "-", "-")
    else:
        for f in analyzed_flows:
            level = f["threat_level"]
            level_str = "[bold red]CRITICAL[/bold red]" if level == "CRITICAL" else "[bold yellow]HIGH[/bold yellow]" if level == "HIGH" else "[bold green]NORMAL[/bold green]"
            
            is_anomaly = f["statistical_anomaly"]
            anomaly_str = "[bold red]YES (Exfiltration Risk)[/bold red]" if is_anomaly else "[dim]No[/dim]"

            table.add_row(
                f["flow_id"],
                f["source_ip"],
                f"{f['bytes_transferred']:,}",
                level_str,
                anomaly_str
            )

    console.print(table)
    console.print(f"\n[bold green]✔ Day 3 Complete:[/bold green] Processed statistical volume outlier detection for [bold cyan]{len(analyzed_flows)}[/bold cyan] network flows.")

if __name__ == "__main__":
    main()
