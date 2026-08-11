"""Evidence-based HTML, JSON, and PDF forensic reports."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from dfir_copilot.config import AppConfig
from dfir_copilot.database import Database, utc_now
from dfir_copilot.engine.hashing import safe_filename


class ReportService:
    def __init__(self, config: AppConfig, database: Database):
        self.config = config
        self.db = database

    def case_bundle(self, case_id: int) -> dict[str, Any]:
        case = self.db.fetch_one("SELECT * FROM cases WHERE id = ?", (case_id,))
        if not case:
            raise ValueError("Case not found")
        evidence = self.db.fetch_all("SELECT * FROM evidence WHERE case_id = ? ORDER BY evidence_number", (case_id,))
        artifacts = self.db.fetch_all("SELECT * FROM artifacts WHERE case_id = ? ORDER BY event_time, id", (case_id,))
        findings = self.db.fetch_all("SELECT * FROM findings WHERE case_id = ? ORDER BY id", (case_id,))
        custody = self.db.fetch_all(
            """
            SELECT c.*, e.evidence_number FROM custody_records c
            LEFT JOIN evidence e ON e.id = c.evidence_id
            WHERE c.case_id = ? ORDER BY c.event_time, c.id
            """,
            (case_id,),
        )
        audit = self.db.fetch_all("SELECT * FROM audit_log WHERE case_id = ? ORDER BY event_time, id", (case_id,))
        return {
            "generated_at": utc_now(),
            "case": case,
            "evidence": evidence,
            "artifacts": artifacts,
            "findings": findings,
            "custody": custody,
            "audit": audit,
        }

    def export_json(self, case_id: int, destination: Path | None = None) -> Path:
        bundle = self.case_bundle(case_id)
        destination = destination or self._path(bundle["case"]["case_number"], "json")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
        self.db.audit(case_id, "REPORT_EXPORTED", f"JSON report exported: {destination.name}")
        return destination

    def export_html(self, case_id: int, destination: Path | None = None) -> Path:
        bundle = self.case_bundle(case_id)
        destination = destination or self._path(bundle["case"]["case_number"], "html")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self._render_html(bundle), encoding="utf-8")
        self.db.audit(case_id, "REPORT_EXPORTED", f"HTML report exported: {destination.name}")
        return destination

    def export_pdf(self, case_id: int, destination: Path | None = None) -> Path:
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        except ImportError as exc:
            raise RuntimeError("PDF export requires reportlab") from exc

        bundle = self.case_bundle(case_id)
        destination = destination or self._path(bundle["case"]["case_number"], "pdf")
        destination.parent.mkdir(parents=True, exist_ok=True)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="TitleCenter", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#123047")))
        styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7.5, leading=10))
        styles.add(ParagraphStyle(name="Finding", parent=styles["BodyText"], fontSize=9, leading=12, leftIndent=6))
        doc = SimpleDocTemplate(
            str(destination), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
            topMargin=15 * mm, bottomMargin=15 * mm,
            title=f"DFIR Report - {bundle['case']['case_number']}", author=bundle["case"]["investigator"],
        )
        story: list[Any] = [
            Paragraph("DFIR COPILOT", styles["TitleCenter"]),
            Paragraph("Digital Forensic Investigation Report", styles["Heading2"]),
            Spacer(1, 5 * mm),
        ]
        case = bundle["case"]
        case_rows = [
            ["Case Number", case["case_number"], "Status", case["status"]],
            ["Case Name", case["name"], "Investigator", case["investigator"]],
            ["Created", case["created_at"], "Generated", bundle["generated_at"]],
        ]
        case_table = Table(case_rows, colWidths=[26 * mm, 62 * mm, 25 * mm, 50 * mm])
        case_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#DCEAF2")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#DCEAF2")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9BB2C1")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story += [
            case_table,
            Spacer(1, 3 * mm),
            Paragraph(f"<b>Scope:</b> {html.escape(case['description'] or 'Not specified')}", styles["Small"]),
            Spacer(1, 5 * mm),
            Paragraph("Executive Findings", styles["Heading2"]),
        ]
        if bundle["findings"]:
            for finding in bundle["findings"]:
                references = ", ".join(json.loads(finding["evidence_refs_json"] or "[]")) or "N/A"
                story.append(Paragraph(
                    f"<b>{html.escape(finding['severity'])} — {html.escape(finding['title'])}</b><br/>"
                    f"{html.escape(finding['description'])}<br/>"
                    f"<font size='7'>References: {html.escape(references)} | "
                    f"MITRE: {html.escape(finding['mitre_id'] or 'N/A')} | Confidence: {finding['confidence']}%</font>",
                    styles["Finding"],
                ))
                story.append(Spacer(1, 2 * mm))
        else:
            story.append(Paragraph("No elevated findings were produced by the analyzed evidence.", styles["BodyText"]))

        story += [Spacer(1, 4 * mm), Paragraph("Evidence Inventory", styles["Heading2"])]
        evidence_rows: list[list[Any]] = [["ID", "Filename", "SHA-256", "Size", "Verified"]]
        for item in bundle["evidence"]:
            evidence_rows.append([
                item["evidence_number"], Paragraph(html.escape(item["original_name"]), styles["Small"]),
                Paragraph(html.escape(item["sha256"]), styles["Small"]), str(item["size_bytes"]),
                "Yes" if item["verified"] else "No",
            ])
        evidence_table = Table(evidence_rows, repeatRows=1, colWidths=[14 * mm, 38 * mm, 78 * mm, 20 * mm, 18 * mm])
        evidence_table.setStyle(self._table_style(colors))
        story += [evidence_table, PageBreak(), Paragraph("Investigation Timeline", styles["Heading2"])]
        timeline_rows: list[list[Any]] = [["Time (UTC)", "Severity", "Artifact", "Description", "Ref"]]
        for item in bundle["artifacts"]:
            timeline_rows.append([
                Paragraph(html.escape(item["event_time"]), styles["Small"]), item["severity"],
                Paragraph(html.escape(item["artifact_type"]), styles["Small"]),
                Paragraph(html.escape(item["description"]), styles["Small"]), item["artifact_ref"],
            ])
        timeline_table = Table(timeline_rows, repeatRows=1, colWidths=[34 * mm, 16 * mm, 30 * mm, 70 * mm, 23 * mm])
        timeline_table.setStyle(self._table_style(colors))
        story += [timeline_table, PageBreak(), Paragraph("Chain of Custody", styles["Heading2"])]
        custody_rows: list[list[Any]] = [["Time", "Evidence", "Action", "Actor", "Notes"]]
        for item in bundle["custody"]:
            custody_rows.append([
                Paragraph(html.escape(item["event_time"]), styles["Small"]), item.get("evidence_number") or "Case",
                Paragraph(html.escape(item["action"]), styles["Small"]),
                Paragraph(html.escape(item["actor"]), styles["Small"]),
                Paragraph(html.escape(item["notes"]), styles["Small"]),
            ])
        custody_table = Table(custody_rows, repeatRows=1, colWidths=[34 * mm, 18 * mm, 38 * mm, 32 * mm, 51 * mm])
        custody_table.setStyle(self._table_style(colors))
        story += [
            custody_table,
            Spacer(1, 8 * mm),
            Paragraph(
                "Analyst note: AI-generated assistance must be independently validated against the cited evidence. "
                "This report records deterministic artifacts and correlations; it does not replace examiner judgment.",
                styles["Small"],
            ),
            Spacer(1, 12 * mm),
            Paragraph(
                "Examiner sign-off: ________________________________ &nbsp;&nbsp;&nbsp; Date: __________________",
                styles["BodyText"],
            ),
        ]
        doc.build(story, onFirstPage=self._page_number, onLaterPages=self._page_number)
        self.db.audit(case_id, "REPORT_EXPORTED", f"PDF report exported: {destination.name}")
        return destination

    @staticmethod
    def _table_style(colors: Any) -> Any:
        from reportlab.platypus import TableStyle

        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123047")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#A8BBC7")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F6F8")]),
            ("PADDING", (0, 0), (-1, -1), 4),
        ])

    @staticmethod
    def _page_number(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColorRGB(0.35, 0.42, 0.46)
        canvas.drawString(16 * 2.83465, 9 * 2.83465, "DFIR Copilot — Evidence-Grounded Report")
        canvas.drawRightString(194 * 2.83465, 9 * 2.83465, f"Page {doc.page}")
        canvas.restoreState()

    def _path(self, case_number: str, extension: str) -> Path:
        stem = safe_filename(f"{case_number}_forensic_report")
        return self.config.report_dir / f"{stem}.{extension}"

    def _render_html(self, bundle: dict[str, Any]) -> str:
        def table(headers: list[str], rows: list[list[Any]]) -> str:
            head = "".join(f"<th>{html.escape(str(value))}</th>" for value in headers)
            body = "".join(
                "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
                for row in rows
            )
            return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

        case = bundle["case"]
        findings = "".join(
            f"<article class='finding {html.escape(item['severity'].lower())}'>"
            f"<strong>{html.escape(item['severity'])} — {html.escape(item['title'])}</strong>"
            f"<p>{html.escape(item['description'])}</p>"
            f"<small>{html.escape(item['evidence_refs_json'])} · MITRE {html.escape(item['mitre_id'] or 'N/A')} · {item['confidence']}%</small>"
            "</article>"
            for item in bundle["findings"]
        ) or "<p>No elevated findings.</p>"
        evidence_table = table(
            ["ID", "Filename", "SHA-256", "Bytes", "Verified"],
            [[item["evidence_number"], item["original_name"], item["sha256"], item["size_bytes"], bool(item["verified"])] for item in bundle["evidence"]],
        )
        timeline_table = table(
            ["Time", "Severity", "Artifact", "Description", "Reference"],
            [[item["event_time"], item["severity"], item["artifact_type"], item["description"], item["artifact_ref"]] for item in bundle["artifacts"]],
        )
        custody_table = table(
            ["Time", "Evidence", "Action", "Actor", "Notes"],
            [[item["event_time"], item.get("evidence_number") or "Case", item["action"], item["actor"], item["notes"]] for item in bundle["custody"]],
        )
        return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>{html.escape(case['case_number'])} DFIR Report</title>
<style>
body{{font-family:Inter,Segoe UI,Arial,sans-serif;margin:40px;color:#17242d;background:#f5f8fa}}main{{max-width:1180px;margin:auto;background:white;padding:38px;border-radius:14px;box-shadow:0 8px 30px #12304718}}h1{{color:#123047;margin-bottom:4px}}h2{{margin-top:32px;color:#1d5068;border-bottom:2px solid #d8e7ee;padding-bottom:8px}}.meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}.meta div{{background:#edf5f8;padding:12px;border-radius:8px}}table{{width:100%;border-collapse:collapse;font-size:12px}}th{{background:#123047;color:white;text-align:left}}th,td{{padding:9px;border:1px solid #cad9df;vertical-align:top}}tr:nth-child(even){{background:#f5f8fa}}.finding{{padding:14px;border-left:5px solid #4e91a8;background:#f4f8fa;margin:10px 0;border-radius:6px}}.critical{{border-color:#b42318}}.high{{border-color:#d97706}}small{{color:#526873}}footer{{margin-top:32px;color:#6a7d86;font-size:11px}}</style></head>
<body><main><h1>DFIR Copilot</h1><p>Evidence-Grounded Digital Forensic Investigation Report</p>
<section class='meta'><div><b>Case</b><br>{html.escape(case['case_number'])}</div><div><b>Investigator</b><br>{html.escape(case['investigator'])}</div><div><b>Status</b><br>{html.escape(case['status'])}</div></section>
<h2>Executive Findings</h2>{findings}<h2>Evidence Inventory</h2>{evidence_table}
<h2>Investigation Timeline</h2>{timeline_table}<h2>Chain of Custody</h2>{custody_table}
<footer>Generated {html.escape(bundle['generated_at'])}. AI assistance must be independently validated against cited evidence.</footer></main></body></html>"""
