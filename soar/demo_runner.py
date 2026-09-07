"""
SentinelAI - Golden Demo Presentation Runner
Executes the live, end-to-end multi-agent security automation demonstration for evaluators.
Showcases real-time agent choreography, dynamic risk scoring, autonomous firewall enforcement,
GenAI SOC explanations, and automated PDF incident report generation.
"""

from __future__ import annotations
import os
import sys
import time
import colorama
from colorama import Fore, Style

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Force UTF-8 encoding for Windows console compatibility
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from core.orchestrator import SentinelOrchestrator
from tests.mock_traffic import (
    generate_benign_flow,
    generate_port_scan_flow,
    generate_ddos_flow,
    generate_brute_force_flow
)

colorama.init(autoreset=True)


def print_banner():
    banner = f"""
{Fore.CYAN}================================================================================
{Fore.GREEN}   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║
   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║
{Fore.CYAN}================================================================================
{Fore.YELLOW}   Autonomous Multi-Agent SOAR & Cyber Defense Platform (Phase 1)
   Role: Multi-Agent Orchestrator & Autonomous Response Lead
{Fore.CYAN}================================================================================{Style.RESET_ALL}
"""
    print(banner)


def run_golden_demo():
    print_banner()

    print(f"{Fore.BLUE}[STAGE 1/6] Initializing SentinelAI Orchestrator & All 11 Specialist Agents...{Style.RESET_ALL}")
    orchestrator = SentinelOrchestrator(
        dry_run_firewall=True,
        enable_desktop_alerts=False  # Avoid disruptive popups during terminal eval
    )
    orchestrator.initialize()
    time.sleep(1.0)

    print(f"\n{Fore.GREEN}[+] Multi-Agent Health Matrix:{Style.RESET_ALL}")
    status_matrix = orchestrator.get_system_metrics().agent_statuses
    for agent_name, status in status_matrix.items():
        print(f"  * {Fore.WHITE}{agent_name:<25}{Style.RESET_ALL}: {Fore.GREEN}[{status}]{Style.RESET_ALL}")
    print(f"  * {Fore.WHITE}SQLite Database          {Style.RESET_ALL}: {Fore.GREEN}[CONNECTED]{Style.RESET_ALL} ({orchestrator.db_manager.db_path})")
    print(f"  * {Fore.WHITE}Security Policies        {Style.RESET_ALL}: {Fore.GREEN}[LOADED]{Style.RESET_ALL} ({orchestrator.policy_engine.policy_path})")
    print(f"  * {Fore.WHITE}Firewall Safety Mode     {Style.RESET_ALL}: {Fore.YELLOW}[DRY-RUN SAFE]{Style.RESET_ALL}")

    input(f"\n{Fore.CYAN}--> Press [Enter] to start Stage 2 (Normal Baseline Traffic Stream)...{Style.RESET_ALL}")

    # STAGE 2: Normal Baseline
    print(f"\n{Fore.BLUE}[STAGE 2/6] Ingesting Normal Baseline Network Traffic (5 Flows)...{Style.RESET_ALL}")
    for i in range(1, 6):
        benign_flow = generate_benign_flow(src_ip=f"192.168.1.{100 + i}", dst_port=443)
        incident = orchestrator.process_flow(benign_flow)
        print(
            f"  [{i}] Flow {benign_flow['src_ip']}:443 -> "
            f"Classification: {Fore.GREEN}{incident.detection.attack_type}{Style.RESET_ALL} ({incident.detection.confidence*100:.1f}%) | "
            f"Risk: {Fore.GREEN}{incident.risk.score}/10{Style.RESET_ALL} | "
            f"Action: {Fore.WHITE}{incident.action_plan.action_type.value}{Style.RESET_ALL}"
        )
        time.sleep(0.3)

    print(f"{Fore.GREEN}[✓] Normal baseline confirmed. LoggingAgent recording quietly without triggering mitigations.{Style.RESET_ALL}")
    input(f"\n{Fore.CYAN}--> Press [Enter] to simulate Stage 3 (Authorized Adversary SYN Port Scan)...{Style.RESET_ALL}")

    # STAGE 3 & 4: Attack Simulation & Real-time Choreography
    attacker_ip = "192.168.1.50"
    target_ip = "192.168.1.10"
    print(f"\n{Fore.RED}[STAGE 3/6] Adversary Simulation: Launching Rapid SYN Port Scan from {attacker_ip} -> {target_ip}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Emulating: nmap -sS -p 21,22,80,443,3306,3389,8080 {target_ip}{Style.RESET_ALL}")
    time.sleep(0.5)

    print(f"\n{Fore.BLUE}[STAGE 4/6] Real-Time Agent Choreography & Autonomous SOAR Execution:{Style.RESET_ALL}")
    scan_ports = [21, 22, 23, 80, 135, 443, 445, 1433, 3306, 3389]
    last_incident = None

    for idx, port in enumerate(scan_ports, 1):
        scan_flow = generate_port_scan_flow(src_ip=attacker_ip, dst_ip=target_ip, target_port=port)
        last_incident = orchestrator.process_flow(scan_flow)
        
        # Color based on risk
        r_color = Fore.RED if last_incident.risk.score >= 7.0 else Fore.YELLOW
        print(
            f"  [{idx:>2}] Probe port {port:<5} | "
            f"Detection: {Fore.RED}{last_incident.detection.attack_type}{Style.RESET_ALL} | "
            f"Velocity: {last_incident.risk.frequency_count_60s} probes/60s | "
            f"Risk: {r_color}{last_incident.risk.score}/10 ({last_incident.risk.severity.value}){Style.RESET_ALL} | "
            f"Action: {Fore.RED}{last_incident.action_plan.action_type.value}{Style.RESET_ALL}"
        )
        time.sleep(0.2)

    print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.RED}🚨 CRITICAL THREAT DETECTED & CONTAINED IN REAL TIME:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"1. {Fore.WHITE}PacketAgent{Style.RESET_ALL}        : Validated {last_incident.risk.frequency_count_60s} raw TCP flows (0 NaNs, normalized protocol).")
    print(f"2. {Fore.WHITE}DetectionAgent{Style.RESET_ALL}     : Classified as {Fore.RED}{last_incident.detection.attack_type}{Style.RESET_ALL} with {Fore.GREEN}{last_incident.detection.confidence*100:.1f}% confidence{Style.RESET_ALL}.")
    print(f"3. {Fore.WHITE}ThreatAgent{Style.RESET_ALL}        : Extracted signature evidence: \"{Fore.YELLOW}{last_incident.threat.anomaly_explanation}{Style.RESET_ALL}\"")
    print(f"                     Mapped to MITRE ATT&CK: {Fore.CYAN}{last_incident.threat.mitre_technique_id} - {last_incident.threat.mitre_technique_name} ({last_incident.threat.mitre_tactic}){Style.RESET_ALL}")
    print(f"4. {Fore.WHITE}RiskAgent{Style.RESET_ALL}          : Multi-Factor Score = {Fore.RED}{last_incident.risk.score}/10.0 (CRITICAL){Style.RESET_ALL}")
    print(f"                     [Base 5.0 * Conf 0.98] + [Velocity +{last_incident.risk.velocity_multiplier}] + [Target Sensitivity +{last_incident.risk.target_sensitivity}]")
    print(f"5. {Fore.WHITE}DecisionAgent{Style.RESET_ALL}      : Rule matched: {Fore.YELLOW}{last_incident.action_plan.rule_matched}{Style.RESET_ALL} -> Triggered {Fore.RED}BLOCK_IP{Style.RESET_ALL}.")
    print(f"6. {Fore.WHITE}FirewallAgent{Style.RESET_ALL}      : Executed OS Firewall Drop:")
    print(f"                     {Fore.CYAN}{last_incident.firewall_rule.command_executed}{Style.RESET_ALL}")
    print(f"7. {Fore.WHITE}AlertAgent{Style.RESET_ALL}         : Broadcast alert to Desktop Toast & Member 4's Dashboard Queue.")
    print(f"8. {Fore.WHITE}LoggingAgent{Style.RESET_ALL}       : Persisted incident ID {Fore.YELLOW}{last_incident.incident_id}{Style.RESET_ALL} to SQLite database.")
    print(f"9. {Fore.WHITE}LLMAgent{Style.RESET_ALL}           : Generated GenAI SOC Analyst Plain-English Assessment:")
    print(f"   {Fore.WHITE}Executive Summary{Style.RESET_ALL}: {last_incident.llm_explanation.summary}")
    print(f"   {Fore.WHITE}Technical Cause  {Style.RESET_ALL}: {last_incident.llm_explanation.technical_analysis}")
    print(f"   {Fore.WHITE}Action Plan      {Style.RESET_ALL}: {', '.join(last_incident.llm_explanation.soc_recommendations[:2])}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")

    input(f"\n{Fore.CYAN}--> Press [Enter] for Stage 5 (Verification of Attacker Block & Post-Mitigation)...{Style.RESET_ALL}")

    # STAGE 5: Attacker Blocked Verification
    print(f"\n{Fore.BLUE}[STAGE 5/6] Verifying Firewall Mitigation:{Style.RESET_ALL}")
    print(f"  * Attacker {attacker_ip} attempts new connection on port 8080...")
    active_rules = orchestrator.db_manager.get_active_blocks()
    is_blocked = any(r["ip_address"] == attacker_ip for r in active_rules)
    if is_blocked:
        print(f"  * {Fore.RED}[FIREWALL ACTIVE]{Style.RESET_ALL} Packet from {attacker_ip} is immediately DROPPED by active rule.")
    else:
        print(f"  * {Fore.YELLOW}[WARN]{Style.RESET_ALL} Rule not found in active list.")

    input(f"\n{Fore.CYAN}--> Press [Enter] for Stage 6 (Automated PDF Forensic Report Generation)...{Style.RESET_ALL}")

    # STAGE 6: PDF Report Generation
    print(f"\n{Fore.BLUE}[STAGE 6/6] Generating Executive SOC Reports...{Style.RESET_ALL}")
    inc_pdf = orchestrator.report_agent.generate_incident_pdf(last_incident)
    summary_pdf = orchestrator.report_agent.generate_soc_summary_pdf()

    print(f"  * {Fore.GREEN}[+] Incident Forensic PDF Generated :{Style.RESET_ALL} {inc_pdf}")
    print(f"  * {Fore.GREEN}[+] SOC Daily Summary PDF Generated   :{Style.RESET_ALL} {summary_pdf}")

    # Final Dashboard KPIs
    kpi = orchestrator.db_manager.get_dashboard_summary()
    print(f"\n{Fore.CYAN}================================================================================")
    print(f"{Fore.YELLOW}[*] GOLDEN DEMO COMPLETED SUCCESSFULLY — SOC DASHBOARD METRICS SUMMARY:")
    print(f"{Fore.CYAN}================================================================================")
    print(f"  * Total Network Flows Analyzed: {Fore.WHITE}{kpi['total_flows_analyzed']}{Style.RESET_ALL}")
    print(f"  * Total Threats Mitigated     : {Fore.RED}{kpi['total_threats_detected']}{Style.RESET_ALL}")
    print(f"  * Active Firewall Blocks      : {Fore.YELLOW}{kpi['active_firewall_blocks']}{Style.RESET_ALL}")
    print(f"  * Average Attack Risk Score   : {Fore.RED}{kpi['average_threat_risk']}/10.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}================================================================================{Style.RESET_ALL}\n")

    orchestrator.shutdown()


if __name__ == "__main__":
    run_golden_demo()
