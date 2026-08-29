"""
SentinelAI - Command Line Interface (CLI) Entrypoint
Provides commands for running the live multi-agent system, synthetic simulation streams,
golden demo presentations, report generation, and status inspection.
"""

from __future__ import annotations
import os
import sys
import time
import argparse
import logging
import colorama
from colorama import Fore, Style

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Force UTF-8 encoding for Windows console compatibility
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from core.orchestrator import SentinelOrchestrator
from tests.mock_traffic import generate_scenario_traffic
from demo_runner import run_golden_demo

colorama.init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s")
logger = logging.getLogger("SentinelAI.CLI")


def cmd_simulate(args):
    """Run continuous or batch synthetic attack traffic simulation."""
    print(f"{Fore.CYAN}[*] Starting SentinelAI in Simulation Mode (Dry-Run: {args.dry_run})...{Style.RESET_ALL}")
    orchestrator = SentinelOrchestrator(
        dry_run_firewall=args.dry_run,
        enable_desktop_alerts=not args.no_desktop
    )
    orchestrator.initialize()

    flows = generate_scenario_traffic()
    print(f"{Fore.GREEN}[+] Loaded {len(flows)} simulated flow vectors.{Style.RESET_ALL}")

    try:
        for idx, f in enumerate(flows, 1):
            inc = orchestrator.process_flow(f)
            r_color = Fore.RED if inc.risk.score >= 7.0 else (Fore.YELLOW if inc.risk.score >= 4.0 else Fore.GREEN)
            print(
                f"[{idx:>2}/{len(flows)}] {inc.flow.src_ip:<15} -> {inc.flow.dst_port:<5} | "
                f"Attack: {r_color}{inc.detection.attack_type:<12}{Style.RESET_ALL} | "
                f"Conf: {inc.detection.confidence*100:>5.1f}% | "
                f"Risk: {r_color}{inc.risk.score:>4.1f}/10{Style.RESET_ALL} | "
                f"Action: {Fore.WHITE}{inc.action_plan.action_type.value}{Style.RESET_ALL}"
            )
            time.sleep(0.4)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Simulation interrupted by user.{Style.RESET_ALL}")
    finally:
        kpi = orchestrator.db_manager.get_dashboard_summary()
        print(f"\n{Fore.CYAN}[+] Simulation Finished. Total Flows: {kpi['total_flows_analyzed']}, Threats Mitigated: {kpi['total_threats_detected']}{Style.RESET_ALL}")
        orchestrator.shutdown()


def cmd_report(args):
    """Generate on-demand executive summary PDF report."""
    print(f"{Fore.CYAN}[*] Compiling SOC Daily Executive Summary Report...{Style.RESET_ALL}")
    orchestrator = SentinelOrchestrator(dry_run_firewall=True, enable_desktop_alerts=False)
    orchestrator.initialize()
    pdf_path = orchestrator.report_agent.generate_soc_summary_pdf()
    print(f"{Fore.GREEN}[+] Report successfully compiled at:{Style.RESET_ALL} {pdf_path}")
    orchestrator.shutdown()


def cmd_status(args):
    """Inspect current database metrics, active firewall blocks, and top adversary IPs."""
    orchestrator = SentinelOrchestrator(dry_run_firewall=True, enable_desktop_alerts=False)
    orchestrator.initialize()
    summary = orchestrator.db_manager.get_dashboard_summary()

    print(f"\n{Fore.CYAN}================================================================================")
    print(f"{Fore.GREEN}                   SENTINELAI - SOC STATUS & THREAT METRICS")
    print(f"{Fore.CYAN}================================================================================{Style.RESET_ALL}")
    print(f"  • Total Network Flows Analyzed: {Fore.WHITE}{summary['total_flows_analyzed']}{Style.RESET_ALL}")
    print(f"  • Total Threats Detected      : {Fore.RED}{summary['total_threats_detected']}{Style.RESET_ALL}")
    print(f"  • Active Firewall Blocks       : {Fore.YELLOW}{summary['active_firewall_blocks']}{Style.RESET_ALL}")
    print(f"  • Average Attack Risk Score    : {Fore.RED}{summary['average_threat_risk']}/10.0{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}[+] Attack Breakdown:{Style.RESET_ALL}")
    for attack, count in summary.get("attack_distribution", {}).items():
        print(f"    - {attack:<16}: {count}")

    print(f"\n{Fore.YELLOW}[+] Top Offending IP Addresses:{Style.RESET_ALL}")
    for off in summary.get("top_offenders", []):
        print(f"    - {off['src_ip']:<16}: {off['incident_count']} incidents (Peak Risk: {off['max_risk_score']}/10)")

    print(f"{Fore.CYAN}================================================================================\n{Style.RESET_ALL}")
    orchestrator.shutdown()


def cmd_server(args):
    """Launch FastAPI backend server with Uvicorn for React frontend."""
    import uvicorn
    print(f"{Fore.CYAN}[*] Launching SentinelAI FastAPI Backend Server on http://{args.host}:{args.port} (Swagger docs: http://{args.host}:{args.port}/docs)...{Style.RESET_ALL}")
    uvicorn.run("api.server:app", host=args.host, port=args.port, reload=args.reload)


def main():
    parser = argparse.ArgumentParser(description="SentinelAI - Multi-Agent Autonomous SOAR Platform")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Demo
    parser_demo = subparsers.add_parser("demo", help="Run the golden presentation demo script")

    # Server (FastAPI backend for React frontend)
    parser_srv = subparsers.add_parser("server", help="Launch FastAPI REST & WebSocket backend server for React dashboard")
    parser_srv.add_argument("--host", type=str, default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser_srv.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser_srv.add_argument("--reload", action="store_true", help="Enable live code reload")

    # Simulate
    parser_sim = subparsers.add_parser("simulate", help="Run synthetic cyberattack simulation stream")
    parser_sim.add_argument("--dry-run", action="store_true", default=True, help="Simulate firewall blocks safely (default: True)")
    parser_sim.add_argument("--live", dest="dry_run", action="store_false", help="Execute live OS firewall rules (Admin required)")
    parser_sim.add_argument("--no-desktop", action="store_true", help="Disable desktop toast popups")

    # Report
    parser_rep = subparsers.add_parser("report", help="Generate SOC summary PDF report")

    # Status
    parser_stat = subparsers.add_parser("status", help="Display system KPIs and active blocks")

    args = parser.parse_args()

    if args.command == "demo" or len(sys.argv) == 1:
        run_golden_demo()
    elif args.command == "server":
        cmd_server(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "status":
        cmd_status(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
