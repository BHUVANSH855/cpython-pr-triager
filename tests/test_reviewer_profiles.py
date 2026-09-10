"""Tests for scripts/triager/reviewer_profiles.py"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import unittest

from scripts.triager.reviewer_profiles import (
    PROFILES,
    co_reviewer_suggestions,
    enrich_experts,
    get_profile,
    subsystem_reviewers,
)


class ProfileDataTests(unittest.TestCase):

    def test_all_named_reviewers_have_profiles(self):
        expected = [
            "markshannon", "iritkatriel", "picnixz", "ZeroIntensity",
            "encukou", "gpshead", "pablogsal", "lysnikolaou",
            "JelleZijlstra", "AlexWaygood", "ericsnowcurrently",
            "brettcannon", "1st1", "asvetlov", "kumaraditya303",
            "rhettinger", "vsajip", "barneygale", "ericvsmith",
            "erlend-aasland", "AA-Turner", "hugovk", "StanFromIreland",
            "pganssle", "gaogaotiantian", "ethanfurman", "FFY00",
            "brandtbucher", "Fidget-Spinner", "serhiy-storchaka",
        ]
        for username in expected:
            self.assertIn(username, PROFILES, f"Missing profile for {username}")

    def test_markshannon_has_bytecode_concerns(self):
        profile = get_profile("markshannon")
        self.assertIsNotNone(profile)
        self.assertIn("bytecodes", profile.subsystems)
        self.assertTrue(any("regen" in c.lower() for c in profile.known_concerns),
                        "markshannon should mention regen-cases in known_concerns")
        self.assertTrue(any("benchmark" in c.lower() or "performance" in c.lower()
                            for c in profile.known_concerns))

    def test_picnixz_has_ssl_concerns(self):
        profile = get_profile("picnixz")
        self.assertIsNotNone(profile)
        self.assertIn("ssl", profile.subsystems)
        self.assertIn("gpshead", profile.co_owners)
        self.assertTrue(any("constant" in c.lower() or "side channel" in c.lower()
                            for c in profile.known_concerns))

    def test_encukou_has_stable_abi_concerns(self):
        profile = get_profile("encukou")
        self.assertIsNotNone(profile)
        self.assertIn("stable ABI", profile.subsystems)
        self.assertTrue(any("stable_abi.toml" in c for c in profile.known_concerns))

    def test_pablogsal_has_regen_commands(self):
        profile = get_profile("pablogsal")
        self.assertIsNotNone(profile)
        self.assertTrue(any("regen-pegen" in c for c in profile.known_concerns),
                        "pablogsal should mention regen-pegen in known_concerns")

    def test_get_profile_strips_at_sign(self):
        profile = get_profile("@markshannon")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.username, "markshannon")

    def test_get_profile_unknown_returns_none(self):
        self.assertIsNone(get_profile("nobody123"))

    def test_all_profiles_have_known_concerns(self):
        for username, profile in PROFILES.items():
            self.assertTrue(
                len(profile.known_concerns) > 0,
                f"{username} has no known_concerns",
            )

    def test_all_profiles_have_subsystems(self):
        for username, profile in PROFILES.items():
            self.assertTrue(
                len(profile.subsystems) > 0,
                f"{username} has no subsystems",
            )

    def test_github_url(self):
        profile = get_profile("markshannon")
        self.assertEqual(profile.github_url, "https://github.com/markshannon")

    def test_profile_as_dict(self):
        profile = get_profile("markshannon")
        d = profile.as_dict()
        self.assertIn("username", d)
        self.assertIn("subsystems", d)
        self.assertIn("known_concerns", d)
        self.assertIn("focus_keywords", d)
        self.assertIn("co_owners", d)
        self.assertIn("typical_response_days", d)
        self.assertIn("github_url", d)


class EnrichExpertsTests(unittest.TestCase):

    def test_enriches_with_profile(self):
        experts = [
            {"owner": "@markshannon", "file": "Python/bytecodes.c",
             "pattern": "Python/bytecodes.c", "line": 1},
        ]
        enriched = enrich_experts(experts)
        self.assertEqual(len(enriched), 1)
        self.assertIn("profile", enriched[0])
        profile = enriched[0]["profile"]
        self.assertIn("bytecodes", profile["subsystems"])
        self.assertTrue(len(profile["known_concerns"]) > 0)

    def test_expert_without_profile_included_unchanged(self):
        experts = [
            {"owner": "@unknown_dev", "file": "some/file.py",
             "pattern": "**/*.py", "line": 1},
        ]
        enriched = enrich_experts(experts)
        self.assertEqual(len(enriched), 1)
        self.assertNotIn("profile", enriched[0])

    def test_empty_experts_list(self):
        self.assertEqual(enrich_experts([]), [])


class SubsystemReviewerTests(unittest.TestCase):

    def test_asyncio_reviewers(self):
        reviewers = subsystem_reviewers("asyncio")
        usernames = [r.username for r in reviewers]
        self.assertIn("1st1", usernames)
        self.assertIn("asvetlov", usernames)
        self.assertIn("kumaraditya303", usernames)

    def test_ssl_reviewers(self):
        reviewers = subsystem_reviewers("ssl")
        usernames = [r.username for r in reviewers]
        self.assertIn("picnixz", usernames)
        self.assertIn("gpshead", usernames)

    def test_typing_reviewers(self):
        reviewers = subsystem_reviewers("typing")
        usernames = [r.username for r in reviewers]
        self.assertIn("JelleZijlstra", usernames)

    def test_unknown_subsystem_empty(self):
        self.assertEqual(subsystem_reviewers("xyzzy_nonexistent"), [])


class CoReviewerSuggestionsTests(unittest.TestCase):

    def test_markshannon_suggests_iritkatriel(self):
        experts = [{"owner": "@markshannon", "file": "Python/compile.c",
                    "pattern": "Python/compile.c", "line": 1}]
        suggestions = co_reviewer_suggestions(experts)
        self.assertIn("iritkatriel", suggestions)

    def test_no_duplicates_with_existing(self):
        experts = [
            {"owner": "@markshannon", "file": "Python/compile.c", "pattern": "", "line": 1},
            {"owner": "@iritkatriel", "file": "Python/compile.c", "pattern": "", "line": 1},
        ]
        suggestions = co_reviewer_suggestions(experts)
        # iritkatriel is already an expert, should not be re-suggested
        self.assertNotIn("iritkatriel", suggestions)

    def test_empty_experts_no_suggestions(self):
        self.assertEqual(co_reviewer_suggestions([]), [])

    def test_max_suggestions_respected(self):
        experts = [{"owner": "@ericsnowcurrently", "file": "Python/import.c",
                    "pattern": "", "line": 1}]
        suggestions = co_reviewer_suggestions(experts, max_suggestions=2)
        self.assertLessEqual(len(suggestions), 2)


class ExpertContextModelTests(unittest.TestCase):
    """Test ExpertContext model via enrich_experts output."""

    def test_expert_context_all_concerns_combines(self):
        from scripts.triager.models import ExpertContext
        ctx = ExpertContext(
            owner="@markshannon",
            file="Python/bytecodes.c",
            pattern="Python/bytecodes.c",
            line=1,
            known_concerns=["Concern A", "Concern B"],
            dynamic_concerns=["Concern B", "Concern C"],
        )
        all_c = ctx.all_concerns
        self.assertIn("Concern A", all_c)
        self.assertIn("Concern B", all_c)
        self.assertIn("Concern C", all_c)
        # Deduplication
        self.assertEqual(all_c.count("Concern B"), 1)

    def test_expert_context_username_strips_at(self):
        from scripts.triager.models import ExpertContext
        ctx = ExpertContext(owner="@markshannon", file="f", pattern="p", line=1)
        self.assertEqual(ctx.username, "markshannon")

    def test_expert_context_as_dict_has_all_fields(self):
        from scripts.triager.models import ExpertContext
        ctx = ExpertContext(
            owner="@picnixz",
            file="Modules/_ssl.c",
            pattern="**/*ssl*",
            line=42,
            subsystems=["ssl", "hashlib"],
            co_owners=["gpshead"],
            known_concerns=["constant time check"],
            approval_rate=0.85,
            typical_response_days=5.0,
        )
        d = ctx.as_dict()
        self.assertEqual(d["owner"], "@picnixz")
        self.assertEqual(d["username"], "picnixz")
        self.assertEqual(d["subsystems"], ["ssl", "hashlib"])
        self.assertEqual(d["approval_rate"], 0.85)
        self.assertIn("all_concerns", d)


if __name__ == "__main__":
    unittest.main()