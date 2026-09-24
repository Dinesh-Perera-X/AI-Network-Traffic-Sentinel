import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.flow_parser import FlowParser

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

    table = Table(title="[bold cyan]📋 Ingested VPC Network Flows[/bold cyan]", border_style="cyan")
    table.add_column("Flow ID", justify="center", style="dim")
    table.add_column("Source IP", style="yellow")
    table.add_column("Dest IP", style="yellow")
    table.add_column("Port", justify="center", style="magenta")
    table.add_column("Protocol", justify="center", style="white")
    table.add_column("Bytes", justify="right", style="cyan")
    table.add_column("Action", justify="center", style="green")

    if not flows:
        table.add_row("-", "No flows found.", "-", "-", "-", "-", "-")
    else:
        for f in flows:
            table.add_row(
                f["flow_id"],
                f["source_ip"],
                f["destination_ip"],
                str(f["destination_port"]),
                f["protocol"],
                f"{f['bytes_transferred']:,}",
                f["action"]
            )

    console.print(table)
    console.print(f"\n[bold green]✔ Day 1 Complete:[/bold green] Ingested [bold cyan]{len(flows)}[/bold cyan] network flow records.")

if __name__ == "__main__":
    main()
