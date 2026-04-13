"""
YARA Scanner — Runs YARA rules against file bytes.

YARA is a pattern-matching tool designed for malware researchers.
Each rule defines:
  - meta:      Description, severity, author tags
  - strings:   Text, hex, or regex patterns to search for
  - condition: Boolean logic combining matches

This scanner:
  1. Loads all .yar files from the rules directory (once, cached)
  2. Provides scan() to run all compiled rules against raw bytes
  3. Returns structured match results with severity and score contributions

============================================================
HOW TO ADD YOUR OWN YARA RULES
============================================================
1. Create a new .yar file in app/engines/rules/
2. Write your rule following the format in existing .yar files
3. The scanner will pick it up automatically on next restart
   (or immediately if you call reload_rules())

Example minimal rule:
------
rule MyCustomRule : tag1 tag2
{
    meta:
        description = "Detects something suspicious"
        severity    = "high"

    strings:
        $s1 = "bad string"   nocase ascii wide
        $s2 = { DE AD BE EF }

    condition:
        any of them
}
------
============================================================
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Rules directory — relative to this file's location
_RULES_DIR = Path(__file__).parent / "rules"

# Severity order for score mapping
_SEVERITY_SCORES: Dict[str, float] = {
    "critical": 85.0,
    "high":     65.0,
    "medium":   35.0,
    "low":      15.0,
    "info":      5.0,
}


@dataclass
class YaraMatch:
    """Represents a single YARA rule that matched."""
    rule_name: str
    tags: List[str]
    meta: Dict[str, Any]
    matched_strings: List[str]   # Human-readable list of which strings matched

    @property
    def severity(self) -> str:
        return str(self.meta.get("severity", "medium")).lower()

    @property
    def description(self) -> str:
        return str(self.meta.get("description", self.rule_name))

    @property
    def score_contribution(self) -> float:
        """Score this match contributes to the overall risk score."""
        return _SEVERITY_SCORES.get(self.severity, 35.0)


@dataclass
class YaraScanResult:
    """Result of running all YARA rules against a file."""
    matched: bool = False
    matches: List[YaraMatch] = field(default_factory=list)
    yara_score: float = 0.0         # 0–100 aggregate score
    error: Optional[str] = None     # Error message if scan failed

    @property
    def findings(self) -> List[str]:
        """Human-readable finding strings for each match."""
        return [
            f"YARA [{m.severity.upper()}] {m.rule_name}: {m.description}"
            for m in self.matches
        ]


class YaraScanner:
    """
    Loads and executes YARA rules against file bytes.

    The compiled rules are cached in memory — loading only happens once
    per process lifetime (or on explicit reload_rules() call).
    """

    _compiled_rules = None   # Module-level cache — shared across all instances
    _rules_loaded: bool = False
    _rules_error: Optional[str] = None

    def __init__(self):
        if not YaraScanner._rules_loaded:
            self._load_rules()

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self, data: bytes, filename: str = "unknown") -> YaraScanResult:
        """
        Run all loaded YARA rules against raw file bytes.

        Args:
            data    : Raw bytes of the file to scan
            filename: Original filename (for logging only)

        Returns:
            YaraScanResult with all matched rules and aggregate score
        """
        result = YaraScanResult()

        if YaraScanner._rules_error:
            result.error = f"YARA rules failed to load: {YaraScanner._rules_error}"
            logger.warning(f"YARA scan skipped for '{filename}': {result.error}")
            return result

        if YaraScanner._compiled_rules is None:
            result.error = "YARA rules not loaded"
            return result

        try:
            raw_matches = YaraScanner._compiled_rules.match(data=data)
        except Exception as e:
            result.error = f"YARA scan error: {e}"
            logger.error(f"YARA scan failed on '{filename}': {e}")
            return result

        if not raw_matches:
            return result

        result.matched = True
        total_score = 0.0

        for match in raw_matches:
            # Build list of matched string identifiers
            matched_str_names = list({
                str(s.identifier) for s in match.strings if s.instances
            })

            yara_match = YaraMatch(
                rule_name=match.rule,
                tags=list(match.tags),
                meta=dict(match.meta),
                matched_strings=matched_str_names,
            )
            result.matches.append(yara_match)

            # Accumulate score (capped at 100)
            total_score += yara_match.score_contribution

        result.yara_score = min(100.0, round(total_score, 1))

        logger.info(
            f"YARA matched {len(result.matches)} rule(s) on '{filename}': "
            f"score={result.yara_score} "
            f"rules=[{', '.join(m.rule_name for m in result.matches)}]"
        )
        return result

    def reload_rules(self) -> bool:
        """Force a reload of YARA rules from disk. Returns True on success."""
        YaraScanner._rules_loaded = False
        YaraScanner._compiled_rules = None
        YaraScanner._rules_error = None
        return self._load_rules()

    def is_available(self) -> bool:
        """Check if YARA is installed and rules loaded successfully."""
        return YaraScanner._rules_loaded and YaraScanner._compiled_rules is not None

    # ── Private helpers ────────────────────────────────────────────────────────

    @classmethod
    def _load_rules(cls) -> bool:
        """
        Compile all .yar files in the rules directory.

        YARA compiles rules upfront — scanning is fast because compilation
        already happened. This is called once at startup.
        """
        try:
            import yara  # Lazy import — requires yara-python
        except ImportError:
            cls._rules_error = "yara-python package not installed"
            cls._rules_loaded = True  # Mark as "attempted" to avoid repeated attempts
            logger.warning(
                "yara-python not installed — YARA scanning disabled. "
                "Install with: pip install yara-python"
            )
            return False

        rule_files = list(_RULES_DIR.glob("*.yar"))

        if not rule_files:
            cls._rules_error = f"No .yar files found in {_RULES_DIR}"
            cls._rules_loaded = True
            logger.warning(cls._rules_error)
            return False

        # Build a filepaths dict: {namespace: path_string}
        # Namespace is the filename without extension — shown in match output
        filepaths: Dict[str, str] = {
            f.stem: str(f) for f in rule_files
        }

        try:
            cls._compiled_rules = yara.compile(filepaths=filepaths)
            cls._rules_loaded = True
            cls._rules_error = None
            logger.info(
                f"YARA: compiled {len(rule_files)} rule file(s) from {_RULES_DIR}: "
                f"{[f.name for f in rule_files]}"
            )
            return True
        except yara.SyntaxError as e:
            cls._rules_error = f"YARA syntax error: {e}"
            cls._rules_loaded = True
            logger.error(f"YARA rule compilation failed: {e}")
            return False
        except Exception as e:
            cls._rules_error = f"Unexpected error compiling YARA rules: {e}"
            cls._rules_loaded = True
            logger.error(cls._rules_error)
            return False
