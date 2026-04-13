"""
Scan Service — Orchestrates the analysis pipeline.

Given an email, runs all available analysis engines, computes
a verdict, and stores the results in the database.
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.email import Email
from app.models.scan import Scan, Verdict, ScanStatus, Classification
from app.engines.text_analyzer import get_text_analyzer
from app.engines.attachment_analyzer import AttachmentAnalyzer

logger = logging.getLogger(__name__)


class ScanService:
    """Orchestrates the full email analysis pipeline."""

    def __init__(self, db: Session):
        self.db = db

    def run_scan(self, email: Email) -> Scan:
        """
        Execute a full scan on an email.

        Runs:
            1. ML Text Analysis    → ai_score
            2. Attachment Analysis → attachment_score  (file engine)

        Future engines:
            3. URL Analysis        → url_score         (not yet wired)
        """
        # Create scan record
        scan = Scan(
            email_id=email.id,
            status=ScanStatus.RUNNING.value,
            started_at=datetime.utcnow(),
        )
        self.db.add(scan)
        self.db.flush()

        try:
            # ── 1. ML Text Analysis ──────────────────────
            text_analyzer = get_text_analyzer()

            # Prefer plain text, fall back to HTML
            text = email.body_text or email.body_html or ""
            ai_result = text_analyzer.analyze(text)

            ai_score = ai_result.confidence
            ai_label = ai_result.label

            # ── 2. URL Analysis (placeholder) ──────────────────
            url_score = 0.0

            # ── 3. Attachment Analysis ─────────────────────────
            attachment_analyzer = AttachmentAnalyzer()
            # Load the attachment ORM objects (already in session via email.attachments)
            att_result = attachment_analyzer.analyze(email.attachments)
            attachment_score = att_result.attachment_score

            # ── 4. Compute Final Verdict ─────────────────
            final_score = self._compute_final_score(
                ai_score, url_score, attachment_score
            )
            classification = self._classify(final_score)

            # Create verdict
            verdict = Verdict(
                scan_id=scan.id,
                final_score=final_score,
                classification=classification,
                ai_score=ai_score,
                ai_label=ai_label,
                url_score=url_score,
                attachment_score=attachment_score,
                breakdown={
                    "ai": {
                        "score": ai_score,
                        "label": ai_label,
                        "is_phishing": ai_result.is_phishing,
                    },
                    "url": {"score": url_score, "note": "Not yet implemented"},
                    "attachment": {
                        "score": att_result.attachment_score,
                        "total_files": att_result.total_files,
                        "analyzed_files": att_result.analyzed_files,
                        "high_risk_files": att_result.high_risk_files,
                        "per_file": att_result.per_file_results,
                    },
                },
            )
            self.db.add(verdict)

            scan.status = ScanStatus.COMPLETE.value
            scan.completed_at = datetime.utcnow()

            self.db.commit()
            # Refresh to load the verdict relationship
            self.db.refresh(scan)

            logger.info(
                f"Scan {scan.id} complete: "
                f"score={final_score:.1f}, class={classification}"
            )
            return scan

        except Exception as e:
            scan.status = ScanStatus.ERROR.value
            scan.completed_at = datetime.utcnow()
            self.db.commit()
            logger.error(f"Scan {scan.id} failed: {e}")
            raise

    def _compute_final_score(
        self, ai_score: float, url_score: float, attachment_score: float
    ) -> float:
        """
        Probabilistic risk accumulation.

        P(risk) = 1 - (1 - p_ai)(1 - p_url)(1 - p_att)

        Each input is 0-100, output is 0-100.
        """
        p_ai = min(ai_score, 100.0) / 100.0
        p_url = min(url_score, 100.0) / 100.0
        p_att = min(attachment_score, 100.0) / 100.0

        p_safe = (1.0 - p_ai) * (1.0 - p_url) * (1.0 - p_att)
        final = (1.0 - p_safe) * 100.0

        return round(min(100.0, final), 1)

    def _classify(self, score: float) -> str:
        """Map a 0-100 score to a classification label."""
        if score >= 70.0:
            return Classification.DANGEROUS.value
        elif score >= 30.0:
            return Classification.SUSPICIOUS.value
        else:
            return Classification.SAFE.value
