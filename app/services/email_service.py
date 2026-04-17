"""
Email Service — IMAP fetching, MIME parsing, and database storage.

Connects to the configured IMAP inbox, fetches new emails using stable
UID-based incremental fetch, parses their structure (headers, body,
attachments), and stores everything in the database.

Bug fixes in this version:
  BUG 1 — message_id now read from RFC 2822 Message-ID header (with hashlib fallback)
  BUG 2 — use_uid=True on IMAPClient; all commands operate on stable UIDs
  BUG 3 — Incremental fetch via FetchState.last_uid (only new UIDs fetched)
  BUG 4 — Attachment filenames sanitized against path traversal
"""

import hashlib
import logging
import os
import re
from datetime import datetime
from typing import Tuple, List, Dict, Any, Optional

from imapclient import IMAPClient
from email import policy
from email.parser import BytesParser
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.email import Email, Attachment
from app.models.fetch_state import FetchState

logger = logging.getLogger(__name__)
settings = get_settings()


class EmailService:
    """Handles email fetching, parsing, and storage."""

    def __init__(self, db: Session):
        self.db = db

    # ── Public API ───────────────────────────────────────

    def fetch_and_store(self, limit: int = 20) -> Tuple[int, int]:
        """
        Fetch new emails (incremental, UID-based) and store them in the database.

        Uses FetchState.last_uid to request only UIDs received since the last
        call.  After storing, FetchState is updated to the highest UID seen.

        Returns:
            (new_count, total_fetched)
        """
        raw_emails, fetched_uids = self._fetch_from_imap(limit)
        new_count = 0

        for email_data in raw_emails:
            # Skip duplicates (dedup on RFC 2822 Message-ID)
            existing = (
                self.db.query(Email)
                .filter(Email.message_id == email_data["message_id"])
                .first()
            )
            if existing:
                continue

            email_obj = self._store_email(email_data)
            if email_obj:
                new_count += 1

        # Update FetchState to the highest UID we received
        if fetched_uids:
            self._update_fetch_state("INBOX", max(fetched_uids))

        self.db.commit()
        return new_count, len(raw_emails)

    # ── IMAP Fetching ────────────────────────────────────

    def _fetch_from_imap(self, limit: int) -> Tuple[List[Dict[str, Any]], List[int]]:
        """
        Connect to IMAP, fetch new emails by UID, disconnect.

        Returns:
            (list of parsed email dicts, list of fetched UIDs)
        """
        # use_uid=True puts ALL commands (search, fetch, copy…) into UID mode.
        # This is the imapclient 3.x way — search_uids() no longer exists.
        client = IMAPClient(
            settings.EMAIL_HOST,
            port=settings.EMAIL_PORT,
            ssl=True,
            use_uid=True,
        )

        try:
            client.login(settings.EMAIL_ADDRESS, settings.EMAIL_PASSWORD)
            client.select_folder("INBOX", readonly=True)

            # BUG 3 FIX — load last seen UID for incremental fetch
            last_uid = self._load_last_uid("INBOX")
            uid_range = f"{last_uid + 1}:*"

            # BUG 2 FIX — search() in UID mode returns stable UIDs
            all_uids: List[int] = client.search(["UID", uid_range])

            # Apply limit — take the highest UIDs (most recent)
            recent_uids = all_uids[-limit:] if len(all_uids) > limit else all_uids
            recent_uids_sorted = list(reversed(recent_uids))  # Most recent first

            emails: List[Dict[str, Any]] = []
            for uid in recent_uids_sorted:
                try:
                    # fetch() with a UID list; IMAPClient handles UID mode automatically
                    raw = client.fetch([uid], ["RFC822"])[uid]
                    parsed = BytesParser(policy=policy.default).parsebytes(
                        raw[b"RFC822"]
                    )
                    emails.append(self._parse_mime(parsed))
                except Exception as e:
                    logger.error(f"Failed to parse email UID {uid}: {e}")

            return emails, recent_uids_sorted

        finally:
            try:
                client.logout()
            except Exception:
                pass

    # ── MIME Parsing ─────────────────────────────────────

    def _parse_mime(self, msg) -> Dict[str, Any]:
        """Extract structured data from a parsed MIME message."""
        html_body = None
        text_body = None
        attachments: List[Dict[str, Any]] = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))

                # Attachment
                if "attachment" in disposition:
                    filename = part.get_filename()
                    if filename:
                        payload = part.get_payload(decode=True)
                        if payload:
                            attachments.append({
                                "filename": filename,
                                "content_type": ctype,
                                "size_bytes": len(payload),
                                "content": payload,
                            })
                    continue

                if ctype == "text/html" and html_body is None:
                    html_body = part.get_content()
                elif ctype == "text/plain" and text_body is None:
                    text_body = part.get_content()
        else:
            ctype = msg.get_content_type()
            if ctype == "text/html":
                html_body = msg.get_content()
            elif ctype == "text/plain":
                text_body = msg.get_content()

        # BUG 1 FIX — use RFC 2822 Message-ID header, not IMAP sequence number
        raw_msg_id = msg.get("Message-ID", "").strip().strip("<>")
        if not raw_msg_id:
            sender = msg.get("From", "")
            subject = msg.get("Subject", "")
            date = msg.get("Date", "")
            raw_msg_id = hashlib.sha256(
                f"{sender}{subject}{date}".encode()
            ).hexdigest()[:64]

        return {
            "message_id": raw_msg_id[:512],
            "sender": str(msg.get("From", "Unknown"))[:512],
            "subject": str(msg.get("Subject", "No Subject"))[:1024],
            "date": str(msg.get("Date", ""))[:256],
            "to_address": str(msg.get("To", ""))[:512],
            "body_html": html_body,
            "body_text": text_body,
            "has_html": html_body is not None,
            "attachments": attachments,
        }

    # ── Database Storage ─────────────────────────────────

    def _store_email(self, data: Dict[str, Any]) -> Optional[Email]:
        """Store a parsed email and its attachments in the database."""
        attachments_data = data.pop("attachments", [])

        email_obj = Email(
            message_id=data["message_id"],
            sender=data["sender"],
            subject=data["subject"],
            date=data.get("date"),
            to_address=data.get("to_address"),
            body_html=data.get("body_html"),
            body_text=data.get("body_text"),
            has_html=data.get("has_html", False),
            has_attachments=len(attachments_data) > 0,
        )
        self.db.add(email_obj)
        self.db.flush()  # Get the email ID

        # Save attachments
        storage_base = settings.ATTACHMENT_DIR
        os.makedirs(storage_base, exist_ok=True)

        for att_data in attachments_data:
            content = att_data.pop("content")
            sha256 = hashlib.sha256(content).hexdigest()

            # Save file to disk
            email_dir = os.path.join(storage_base, str(email_obj.id))
            os.makedirs(email_dir, exist_ok=True)

            # BUG 4 FIX — sanitize filename to prevent path traversal
            safe_name = self._sanitize_filename(att_data["filename"], sha256)
            filepath = os.path.join(email_dir, safe_name)

            try:
                with open(filepath, "wb") as f:
                    f.write(content)
            except Exception as e:
                logger.error(f"Failed to save attachment {att_data['filename']}: {e}")
                filepath = None

            att_obj = Attachment(
                email_id=email_obj.id,
                filename=att_data["filename"],  # store original name in DB
                content_type=att_data.get("content_type"),
                size_bytes=att_data.get("size_bytes", 0),
                sha256_hash=sha256,
                storage_path=filepath,
            )
            self.db.add(att_obj)

        return email_obj

    # ── FetchState helpers ────────────────────────────────

    def _load_last_uid(self, mailbox: str) -> int:
        """Return the last stored UID for the given mailbox, or 0 if none."""
        state = (
            self.db.query(FetchState)
            .filter(FetchState.mailbox == mailbox)
            .first()
        )
        return state.last_uid if state else 0

    def _update_fetch_state(self, mailbox: str, max_uid: int) -> None:
        """
        Upsert the FetchState row for the given mailbox.

        Creates the row on first call; updates last_uid on subsequent calls.
        """
        state = (
            self.db.query(FetchState)
            .filter(FetchState.mailbox == mailbox)
            .first()
        )
        if state is None:
            state = FetchState(mailbox=mailbox)
            self.db.add(state)

        state.last_uid = max_uid
        state.last_fetched_at = datetime.utcnow()
        # Caller commits

    # ── Security helpers ──────────────────────────────────

    @staticmethod
    def _sanitize_filename(filename: str, sha256: str) -> str:
        """
        Strip path components and dangerous characters from an attachment filename.

        Prefixes the first 8 hex chars of the file's SHA-256 to guarantee
        uniqueness even when two attachments share the same sanitized name.

        Example:
            "../../etc/passwd"  → "ab12cd34_etc_passwd"
            "invoice (1).pdf"   → "ab12cd34_invoice__1_.pdf"
        """
        # Remove any path traversal components
        safe = os.path.basename(filename)
        # Replace anything that is not a word char, space, dash, underscore, or dot
        safe = re.sub(r"[^\w\s\-_\.]", "_", safe)
        # Collapse multiple dots (e.g. "....") to prevent hiding extension tricks
        safe = re.sub(r"\.{2,}", ".", safe)
        safe = safe.strip(" .")
        if not safe:
            safe = "attachment"
        return f"{sha256[:8]}_{safe}"
