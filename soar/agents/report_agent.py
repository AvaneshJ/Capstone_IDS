"""
SentinelAI - Report Generation Agent
Generates professional PDF Incident Reports and Daily SOC Summary Reports
using ReportLab with clean Markdown/HTML fallbacks.
"""

from __future__ import annotations
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from agents.base_agent import BaseAgent
from core.schemas import Incident
from database.db_manager import DatabaseManager
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.ReportAgent")

DEFAULT_REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


class ReportAgent(BaseAgent):
    """
    SOC Executive & Forensic Report Generator.
    Produces high-fidelity PDF documents detailing incidents, risk forensics,
    MITRE mappings, and autonomous firewall mitigations.
    """

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        reports_dir: str = DEFAULT_REPORTS_DIR,
        event_bus: Optional[EventBus] = None
    ):
        super().__init__(name="ReportAgent", event_bus=event_bus)
        self.db_manager = db_manager or DatabaseManager()
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def _on_initialize(self) -> None:
        if self.event_bus:
            self.event_bus.subscribe("report.request", self.process, priority=10, agent_name=self.name)

    def _handle_event(self, event: Event) -> Optional[str]:
        data = event.data
        if isinstance(data, Incident):
            return self.generate_incident_pdf(data)
        elif isinstance(data, dict) and data.get("type") == "summary":
            return self.generate_soc_summary_pdf()
        return None

    def generate_incident_pdf(self, incident: Incident, output_filename: Optional[str] = None) -> str:
        """
        Generate a detailed forensic PDF report for an individual critical incident.
        """
        if not output_filename:
            ts_str = datetime.fromtimestamp(incident.timestamp).strftime("%Y%m%d_%H%M%S")
            output_filename = f"Incident_{incident.incident_id[:8]}_{ts_str}.pdf"
            
        pdf_path = os.path.join(self.reports_dir, output_filename)

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

            doc = SimpleDocTemplate(pdf_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            elements = []

            # Custom styles
            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontSize=22,
                leading=26,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=6
            )
            subtitle_style = ParagraphStyle(
                "DocSubtitle",
                parent=styles["Normal"],
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#64748b")
            )
            section_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Heading2"],
                fontSize=14,
                leading=18,
                textColor=colors.HexColor("#1e293b"),
                spaceBefore=12,
                spaceAfter=6
            )
            body_style = ParagraphStyle(
                "BodyText",
                parent=styles["Normal"],
                fontSize=10,
                leading=14,
                textColor=colors.HexColor("#334155")
            )

            # Header Banner
            elements.append(Paragraph("🛡️ <b>SentinelAI Security Operations Center</b>", title_style))
            elements.append(Paragraph(f"Autonomous Incident Response & Forensic Report | Incident ID: <b>{incident.incident_id}</b>", subtitle_style))
            elements.append(Paragraph(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
            elements.append(Spacer(1, 10))
            elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563eb"), spaceAfter=15))

            # Incident Overview Table
            sev_color = "#dc2626" if incident.risk.severity.value == "CRITICAL" else "#ea580c"
            data_overview = [
                ["Field", "Value", "Field", "Value"],
                ["Attack Type", incident.detection.attack_type, "Detection Confidence", f"{incident.detection.confidence*100:.1f}%"],
                ["Risk Score", f"{incident.risk.score}/10.0 ({incident.risk.severity.value})", "Autonomous Action", incident.action_plan.action_type.value],
                ["Source IP", incident.flow.src_ip, "Destination IP / Port", f"{incident.flow.dst_ip}:{incident.flow.dst_port}"],
                ["Protocol", f"IP Proto {incident.flow.protocol}", "Rule Matched", incident.action_plan.rule_matched],
            ]

            t_overview = Table(data_overview, colWidths=[110, 160, 120, 150])
            t_overview.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            elements.append(t_overview)
            elements.append(Spacer(1, 15))

            # Threat Forensics & MITRE ATT&CK
            elements.append(Paragraph("1. Threat Analysis & MITRE ATT&CK Mapping", section_style))
            mitre_data = [
                ["MITRE Technique ID", incident.threat.mitre_technique_id],
                ["Technique Name", incident.threat.mitre_technique_name],
                ["Tactic", incident.threat.mitre_tactic],
                ["Signature Match", incident.threat.signature_match],
                ["Forensic Explanation", incident.threat.anomaly_explanation],
            ]
            t_mitre = Table(mitre_data, colWidths=[150, 390])
            t_mitre.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_mitre)
            elements.append(Spacer(1, 15))

            # Forensic Indicators List
            elements.append(Paragraph("2. Forensic Evidence Indicators", section_style))
            for idx, ind in enumerate(incident.threat.indicators, 1):
                elements.append(Paragraph(f"• <b>Indicator {idx}:</b> {ind}", body_style))
            elements.append(Spacer(1, 15))

            # GenAI SOC Analyst Briefing
            if incident.llm_explanation:
                elements.append(Paragraph("3. GenAI SOC Analyst Plain-English Assessment", section_style))
                elements.append(Paragraph(f"<b>Executive Summary:</b> {incident.llm_explanation.summary}", body_style))
                elements.append(Spacer(1, 4))
                elements.append(Paragraph(f"<b>Technical Root Cause:</b> {incident.llm_explanation.technical_analysis}", body_style))
                elements.append(Spacer(1, 6))
                elements.append(Paragraph("<b>Recommended Next Steps:</b>", body_style))
                for rec in incident.llm_explanation.soc_recommendations:
                    elements.append(Paragraph(f"  → {rec}", body_style))
                elements.append(Spacer(1, 15))

            # Autonomous Firewall Actions
            elements.append(Paragraph("4. Autonomous Enforcement & Mitigation State", section_style))
            if incident.firewall_rule:
                fw_data = [
                    ["Firewall Action", incident.firewall_rule.action],
                    ["Rule Name", incident.firewall_rule.rule_name],
                    ["Status", incident.firewall_rule.status],
                    ["Command Executed", incident.firewall_rule.command_executed],
                ]
            else:
                fw_data = [
                    ["Action Plan", incident.action_plan.action_type.value],
                    ["Rationale", incident.action_plan.rationale],
                ]

            t_fw = Table(fw_data, colWidths=[150, 390])
            t_fw.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ]))
            elements.append(t_fw)

            doc.build(elements)
            logger.info("Generated incident PDF report at: %s", pdf_path)
            return pdf_path

        except Exception as exc:
            logger.error("ReportLab PDF generation failed: %s. Generating Markdown fallback.", exc)
            return self._generate_markdown_incident_report(incident, pdf_path.replace(".pdf", ".md"))

    def generate_soc_summary_pdf(self, output_filename: Optional[str] = None) -> str:
        """
        Generate a comprehensive Daily/Shift SOC Executive Summary PDF report.
        """
        if not output_filename:
            ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"SOC_Summary_Report_{ts_str}.pdf"

        pdf_path = os.path.join(self.reports_dir, output_filename)
        summary = self.db_manager.get_dashboard_summary()
        top_offenders = self.db_manager.get_top_offending_ips(limit=5)
        recent_incidents = self.db_manager.get_recent_incidents(limit=10)

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

            doc = SimpleDocTemplate(pdf_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            elements = []

            title_style = ParagraphStyle("DocTitle", parent=styles["Heading1"], fontSize=22, leading=26, textColor=colors.HexColor("#0f172a"))
            subtitle_style = ParagraphStyle("DocSubtitle", parent=styles["Normal"], fontSize=10, leading=14, textColor=colors.HexColor("#64748b"))
            section_style = ParagraphStyle("SectionHeading", parent=styles["Heading2"], fontSize=14, leading=18, textColor=colors.HexColor("#1e293b"), spaceBefore=12, spaceAfter=6)

            # Header
            elements.append(Paragraph("🛡️ <b>SentinelAI - Daily SOC Executive Summary</b>", title_style))
            elements.append(Paragraph(f"Autonomous SOAR & Multi-Agent Network Defense Telemetry | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
            elements.append(Spacer(1, 10))
            elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563eb"), spaceAfter=15))

            # KPIs Summary Cards Table
            kpi_data = [
                ["Total Flows Analyzed", "Total Threats Detected", "Active Firewall Blocks", "Average Threat Risk"],
                [
                    str(summary.get("total_flows_analyzed", 0)),
                    str(summary.get("total_threats_detected", 0)),
                    str(summary.get("active_firewall_blocks", 0)),
                    f"{summary.get('average_threat_risk', 0.0)}/10.0"
                ]
            ]
            t_kpi = Table(kpi_data, colWidths=[135, 135, 135, 135])
            t_kpi.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 1), (-1, 1), 14),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(t_kpi)
            elements.append(Spacer(1, 15))

            # Top Offending Adversary IPs
            elements.append(Paragraph("1. Top Offending Adversary IPs", section_style))
            offender_rows = [["Attacker IP", "Incident Count", "Peak Risk", "Attacks Observed", "Last Seen"]]
            for off in top_offenders:
                last_seen_str = datetime.fromtimestamp(off.get("last_seen", 0)).strftime("%H:%M:%S")
                offender_rows.append([
                    off.get("src_ip", ""),
                    str(off.get("incident_count", 0)),
                    f"{off.get('max_risk_score', 0.0)}/10",
                    off.get("attack_types", ""),
                    last_seen_str
                ])
            if len(offender_rows) == 1:
                offender_rows.append(["No malicious IPs recorded", "-", "-", "-", "-"])

            t_off = Table(offender_rows, colWidths=[120, 90, 80, 160, 90])
            t_off.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            elements.append(t_off)
            elements.append(Spacer(1, 15))

            # Recent Incidents Table
            elements.append(Paragraph("2. Recent Autonomous Incident Chronicle", section_style))
            inc_rows = [["Timestamp", "Source IP", "Attack Type", "Risk", "Action Enforced"]]
            for inc in recent_incidents[:8]:
                ts = datetime.fromtimestamp(inc.get("timestamp", 0)).strftime("%H:%M:%S")
                inc_rows.append([
                    ts,
                    inc.get("src_ip", ""),
                    inc.get("attack_type", ""),
                    f"{inc.get('risk_score', 0.0)} ({inc.get('severity', '')})",
                    inc.get("action_taken", "")
                ])
            if len(inc_rows) == 1:
                inc_rows.append(["No recent incidents", "-", "-", "-", "-"])

            t_inc = Table(inc_rows, colWidths=[90, 110, 110, 110, 120])
            t_inc.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            elements.append(t_inc)

            doc.build(elements)
            logger.info("Generated SOC Summary PDF report at: %s", pdf_path)
            return pdf_path

        except Exception as exc:
            logger.error("SOC Summary PDF generation failed: %s", exc)
            return self._generate_markdown_summary_report(summary, pdf_path.replace(".pdf", ".md"))

    def _generate_markdown_incident_report(self, incident: Incident, output_path: str) -> str:
        """Markdown fallback report generator."""
        content = f"""# SentinelAI Incident Forensic Report
**Incident ID:** `{incident.incident_id}`
**Timestamp:** {datetime.fromtimestamp(incident.timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')}
**Status:** {incident.status}

## Threat Classification
- **Attack Type:** {incident.detection.attack_type}
- **Confidence:** {incident.detection.confidence * 100:.1f}%
- **Risk Score:** {incident.risk.score}/10.0 ({incident.risk.severity.value})
- **Source IP:** `{incident.flow.src_ip}` -> **Target Port:** `{incident.flow.dst_port}`

## MITRE ATT&CK Mapping
- **Technique:** {incident.threat.mitre_technique_id} - {incident.threat.mitre_technique_name}
- **Tactic:** {incident.threat.mitre_tactic}
- **Signature:** `{incident.threat.signature_match}`

## Forensic Indicators
""" + "\n".join(f"- {ind}" for ind in incident.threat.indicators) + f"""

## Autonomous Mitigation Action
- **Action Taken:** `{incident.action_plan.action_type.value}`
- **Rule Matched:** `{incident.action_plan.rule_matched}`
- **Rationale:** {incident.action_plan.rationale}
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path

    def _generate_markdown_summary_report(self, summary: Dict[str, Any], output_path: str) -> str:
        """Markdown fallback summary generator."""
        content = f"""# SentinelAI SOC Daily Summary Report
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## High-Level KPIs
- **Total Flows Analyzed:** {summary.get('total_flows_analyzed', 0)}
- **Total Threats Detected:** {summary.get('total_threats_detected', 0)}
- **Active Firewall Blocks:** {summary.get('active_firewall_blocks', 0)}
- **Average Threat Risk:** {summary.get('average_threat_risk', 0.0)}/10.0
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
