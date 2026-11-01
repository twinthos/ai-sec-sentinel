"""Tests for Twinthos Sentinel pure functions."""
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys, json, tempfile
sys.path.insert(0, str(Path(__file__).parent.parent))
from ai_sec_sentinel import is_ai_related, severity_rank, extract_fix_version, filter_new, atomic_write


class TestIsAiRelated(unittest.TestCase):
    def test_direct_keyword_hit(self):
        assert is_ai_related({"title": "LangChain RCE", "content_text": "", "summary": ""})

    def test_rag_as_word(self):
        # "rag" is a real AI keyword (RAG = Retrieval Augmented Generation)
        assert is_ai_related({"title": "rag", "content_text": "", "summary": ""})

    def test_rag_substring_no_false_positive(self):
        # "program" contains "rag" but should not match word-boundary
        assert not is_ai_related({"title": "program", "content_text": "", "summary": ""})
        assert not is_ai_related({"title": "tragedy", "content_text": "", "summary": ""})
        assert not is_ai_related({"title": "magent", "content_text": "", "summary": ""})

    def test_infra_keyword_requires_ai_keyword(self):
        entry = {"title": "Postgres RCE", "content_text": "database", "summary": ""}
        assert not is_ai_related(entry)

    def test_ai_infra_combo_with_real_ai_keyword(self):
        entry = {"title": "ClickHouse RCE in LangChain pipeline", "content_text": "", "summary": ""}
        assert is_ai_related(entry)


class TestSeverityRank(unittest.TestCase):
    def test_cvss_numeric(self):
        assert severity_rank({"cvss": 9.8}) == 3
        assert severity_rank({"cvss": 7.5}) == 2
        assert severity_rank({"cvss": 5.0}) == 1
        assert severity_rank({"cvss": 0.0}) == 0

    def test_severity_text(self):
        assert severity_rank({"severity": {"label": "CRITICAL"}}) == 3
        assert severity_rank({"severity": {"label": "HIGH"}}) == 2
        assert severity_rank({"severity": {"label": "MEDIUM"}}) == 1
        assert severity_rank({"severity": {"label": "LOW"}}) == 0

    def test_fallback(self):
        assert severity_rank({}) == 0


class TestExtractFixVersion(unittest.TestCase):
    def test_valid_version(self):
        assert extract_fix_version({"content_text": "fixed in 1.2.3"}) == "1.2.3"
        assert extract_fix_version({"content_text": "upgrade to 2.0"}) == "2.0"

    def test_prose_rejected(self):
        assert extract_fix_version({"content_text": "version control"}) is None
        assert extract_fix_version({"content_text": "open source version"}) is None


class TestFilterNew(unittest.TestCase):
    def test_filters_old(self):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        entries = [
            {"id": "CVE-1", "date_published": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")},
            {"id": "CVE-2", "date_published": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
        ]
        out = filter_new(entries, since)
        assert len(out) == 1
        assert out[0]["id"] == "CVE-2"


class TestAtomicWrite(unittest.TestCase):
    def test_writes_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.json"
            atomic_write(p, '{"ok": true}')
            assert p.exists()
            assert json.loads(p.read_text()) == {"ok": True}


if __name__ == "__main__":
    unittest.main()
