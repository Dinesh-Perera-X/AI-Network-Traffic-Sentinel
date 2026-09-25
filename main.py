import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.flow_parser import FlowParser
from analyzers.scan_detector import ScanDetector

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
    analyzed_flows = ScanDetector.evaluate_flows(flows)

    table = Table(title="[bold red]🔍 Day 2: Port-Scanning & Brute-Force Detection[/bold red]", border_style="red")
    table.add_column("Flow ID", justify="center", style="dim")
    table.add_column("Source IP", style="yellow")
    table.add_column("Port", justify="center", style="magenta")
    table.add_column("Detected Behavior", style="cyan")
    table.add_column("Threat Level", justify="center")

    if not analyzed_flows:
        table.add_row("-", "No flows found.", "-", "-", "-")
    else:
        for f in analyzed_flows:
            level = f["threat_level"]
            if level == "CRITICAL":
                level_str = "[bold red]CRITICAL[/bold red]"
            elif level == "HIGH":
                level_str = "[bold yellow]HIGH[/bold yellow]"
            else:
                level_str = "[bold green]NORMAL[/bold green]"

            table.add_row(
                f["flow_id"],
                f["source_ip"],
                str(f["destination_port"]),
                f["detected_behavior"],
                level_str
            )

    console.print(table)
    console.print(f"\n[bold green]✔ Day 2 Complete:[/bold green] Evaluated heuristics for [bold cyan]{len(analyzed_flows)}[/bold cyan] network flows.")

if __name__ == "__main__":
    main()
