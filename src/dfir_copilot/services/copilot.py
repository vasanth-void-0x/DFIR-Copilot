"""Evidence-grounded Copilot with local fallback and optional Groq inference."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from dfir_copilot.config import AppConfig
from dfir_copilot.database import Database, utc_now
from dfir_copilot.models import CopilotResponse, SEVERITY_ORDER


class CopilotService:
    def __init__(self, config: AppConfig, database: Database):
        self.config = config
        self.db = database

    @property
    def cloud_available(self) -> bool:
        return bool(self.config.groq_api_key)

    def ask(self, case_id: int, question: str, use_cloud: bool = False) -> CopilotResponse:
        question = question.strip()
        if not question:
            raise ValueError("Enter a question")
        context = self._context(case_id)
        if use_cloud and self.cloud_available:
            try:
                response = self._ask_groq(question, context)
            except (OSError, ValueError, urllib.error.URLError, TimeoutError):
                response = self._offline_answer(question, context, mode="Offline fallback")
        else:
            response = self._offline_answer(question, context, mode="Offline grounded")
        self.db.execute(
            """
            INSERT INTO copilot_history(case_id, question, answer, citations_json, confidence, mode, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                question,
                response.answer,
                self.db.json(response.citations),
                response.confidence,
                response.mode,
                utc_now(),
            ),
        )
        self.db.audit(case_id, "COPILOT_QUERY", f"Copilot answered in {response.mode} mode")
        return response

    def _context(self, case_id: int) -> dict[str, Any]:
        case = self.db.fetch_one("SELECT * FROM cases WHERE id = ?", (case_id,))
        artifacts = self.db.fetch_all(
            """
            SELECT artifact_ref, artifact_type, event_time, source, description, severity, mitre_id
            FROM artifacts WHERE case_id = ? ORDER BY event_time, id LIMIT 300
            """,
            (case_id,),
        )
        findings = self.db.fetch_all(
            """
            SELECT finding_ref, title, severity, category, description, evidence_refs_json,
                   mitre_id, confidence
            FROM findings WHERE case_id = ? ORDER BY id LIMIT 100
            """,
            (case_id,),
        )
        return {"case": case or {}, "artifacts": artifacts, "findings": findings}

    def _offline_answer(self, question: str, context: dict[str, Any], mode: str) -> CopilotResponse:
        artifacts = context["artifacts"]
        findings = context["findings"]
        q = question.lower()
        if not artifacts:
            return CopilotResponse(
                "Insufficient evidence. Import and analyze evidence before asking investigation questions.",
                [],
                100,
                mode,
            )

        suspicious = [
            row
            for row in artifacts
            if SEVERITY_ORDER.get(row.get("severity", "Info"), 0) >= SEVERITY_ORDER["Medium"]
        ]
        selected: list[dict[str, Any]] = []
        if any(word in q for word in ("begin", "start", "initial", "first")):
            selected = suspicious[:3] or artifacts[:3]
            lead = "The earliest relevant activity in the analyzed evidence is:"
        elif "powershell" in q:
            selected = [row for row in artifacts if "powershell" in (row["artifact_type"] + row["description"]).lower()][:5]
            lead = "PowerShell-related evidence shows:"
        elif any(word in q for word in ("network", "connection", "ip", "dns")):
            selected = [
                row for row in artifacts
                if any(token in (row["artifact_type"] + row["description"]).lower() for token in ("network", "connection", "dns", "ip"))
            ][:5]
            lead = "Network-related evidence shows:"
        elif any(word in q for word in ("delete", "deleted", "anti-forensic")):
            selected = [row for row in artifacts if "delet" in (row["artifact_type"] + row["description"]).lower()][:5]
            lead = "Deleted-file evidence shows:"
        elif any(word in q for word in ("finding", "risk", "suspicious", "summary", "happen")) and findings:
            lines: list[str] = []
            citations: list[str] = []
            for finding in findings[:5]:
                refs = json.loads(finding["evidence_refs_json"] or "[]")
                citations.extend(refs)
                lines.append(f"• {finding['severity']}: {finding['title']} — {finding['description']}")
            answer = "Evidence-supported findings:\n" + "\n".join(lines)
            return CopilotResponse(answer, list(dict.fromkeys(citations)), 92, mode)
        else:
            selected = suspicious[:5] or artifacts[:5]
            lead = "Based on the analyzed case evidence:"

        if not selected:
            return CopilotResponse(
                "Insufficient evidence for that question. No matching artifacts were found in this case.",
                [],
                100,
                mode,
            )
        lines = [
            f"• {row['event_time']}: {row['description']} [{row['artifact_ref']}]"
            for row in selected
        ]
        citations = [row["artifact_ref"] for row in selected]
        return CopilotResponse(f"{lead}\n" + "\n".join(lines), citations, 90, mode)

    def _ask_groq(self, question: str, context: dict[str, Any]) -> CopilotResponse:
        valid_refs = {
            row["artifact_ref"] for row in context["artifacts"]
        } | {row["finding_ref"] for row in context["findings"]}
        system = (
            "You are an evidence-grounded DFIR assistant. Use only the supplied structured evidence. "
            "Never invent events, timestamps, identities, IPs, or conclusions. If the evidence is not enough, "
            "say 'Insufficient evidence'. Return JSON only with keys answer, citations, confidence. "
            "Citations must be artifact_ref or finding_ref values from the context. Confidence is 0-100."
        )
        compact_context = json.dumps(context, ensure_ascii=False)[:60000]
        payload = {
            "model": self.config.groq_model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": f"CASE CONTEXT:\n{compact_context}\n\nQUESTION:\n{question}"},
            ],
        }
        request = urllib.request.Request(
            self.config.groq_base_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.groq_api_key}",
                "Content-Type": "application/json",
                "User-Agent": "DFIR-Copilot/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            outer = json.loads(response.read().decode("utf-8"))
        content = outer["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        citations = [str(ref) for ref in parsed.get("citations", []) if str(ref) in valid_refs]
        answer = str(parsed.get("answer", "")).strip()
        if not answer:
            raise ValueError("Empty model answer")
        if not citations and "insufficient evidence" not in answer.lower():
            raise ValueError("Ungrounded model answer")
        confidence = max(0, min(100, int(parsed.get("confidence", 70))))
        return CopilotResponse(answer, citations, confidence, "Groq grounded")

