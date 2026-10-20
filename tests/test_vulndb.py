"""Testes de vulndb: funções puras e as consultas com fetch_json simulado. Nenhum acesso à rede."""
import json
import os
import tempfile
import unittest
import urllib.request
from unittest import mock

from stingward import vulndb
from stingward.checks import deps
from stingward.model import Context
from stingward.net import NetError

_NO_NET = mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("network access during tests"))


def setUpModule():
    _NO_NET.start()


def tearDownModule():
    _NO_NET.stop()


# --------------------------------------------------------------------------- CVSS 3.x


class Cvss3Score(unittest.TestCase):
    KNOWN = [  # (vector, base score from the FIRST CVSS 3.1 calculator)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # temporal/environmental metrics do not change the base score
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C", 9.8),
        # metric order does not matter
        ("CVSS:3.1/S:U/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N", 9.8),
    ]

    def test_known_vectors(self):
        for vector, want in self.KNOWN:
            with self.subTest(vector=vector):
                self.assertEqual(vulndb.cvss3_score(vector), want)

    def test_no_impact_is_zero(self):
        self.assertEqual(vulndb.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertEqual(vulndb.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N"), 0.0)

    def test_invalid_vectors_return_none(self):
        bad = ["", "lixo", "CVSS:3.1", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A", "CVSS:3.1/AV:N/AC:L/PR:Z/UI:N/S:U/C:H/I:H/A:H",
               "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "AV:N/AC:L/Au:N/C:P/I:P/A:P"]
        for vector in bad:
            with self.subTest(vector=vector):
                self.assertIsNone(vulndb.cvss3_score(vector))

    def test_vector_without_prefix(self):
        self.assertEqual(vulndb.cvss3_score("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"), 4.2)
        self.assertEqual(vulndb.cvss3_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertIsNone(vulndb.cvss3_score(None))

    def test_roundup_is_float_safe(self):
        self.assertEqual(vulndb._roundup(4.000000000000001), 4.0)  # naive ceil would give 4.1
        self.assertEqual(vulndb._roundup(4.0), 4.0)
        self.assertEqual(vulndb._roundup(4.02), 4.1)
        self.assertEqual(vulndb._roundup(4.1), 4.1)
        self.assertEqual(vulndb._roundup(0.0), 0.0)


# --------------------------------------------------------------------------- severidade


class ScoreToSev(unittest.TestCase):
    def test_boundaries(self):
        cases = [(0, "info"), (0.0, "info"), (-1, "info"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
                 (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10, "critical"), (10.0, "critical")]
        for score, want in cases:
            with self.subTest(score=score):
                self.assertEqual(vulndb.score_to_sev(score), want)


class SeverityOf(unittest.TestCase):
    CRIT = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}  # 9.8
    MED = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}  # 5.5

    def test_database_specific_label(self):
        for label, want in [("LOW", "low"), ("MODERATE", "medium"), ("MEDIUM", "medium"), ("HIGH", "high"),
                            ("CRITICAL", "critical"), ("critical", "critical"), ("Moderate", "medium")]:
            with self.subTest(label=label):
                self.assertEqual(vulndb.severity_of({"database_specific": {"severity": label}}), (want, None))

    def test_cvss_vector_only(self):
        self.assertEqual(vulndb.severity_of({"severity": [self.CRIT]}), ("critical", 9.8))
        self.assertEqual(vulndb.severity_of({"severity": [self.MED]}), ("medium", 5.5))
        for typ in ("CVSS_V31", "CVSS_V30"):
            with self.subTest(type=typ):
                self.assertEqual(vulndb.severity_of({"severity": [dict(self.CRIT, type=typ)]}), ("critical", 9.8))

    def test_label_wins_over_vector_but_score_is_kept(self):
        v = {"severity": [self.CRIT], "database_specific": {"severity": "MODERATE"}}
        self.assertEqual(vulndb.severity_of(v), ("medium", 9.8))

    def test_first_valid_v3_vector_is_used(self):
        v4 = {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
        broken = {"type": "CVSS_V3", "score": "CVSS:3.1/garbage"}
        self.assertEqual(vulndb.severity_of({"severity": [v4, broken, self.MED, self.CRIT]}), ("medium", 5.5))
        self.assertEqual(vulndb.severity_of({"severity": [v4]}), (None, None))
        self.assertEqual(vulndb.severity_of({"severity": [{"type": "CVSS_V3"}]}), (None, None))

    def test_affected_level_labels(self):
        v = {"affected": [{"package": {"name": "a"}}, {"database_specific": {"severity": "HIGH"}}]}
        self.assertEqual(vulndb.severity_of(v), ("high", None))
        v = {"affected": [{"ecosystem_specific": {"severity": "LOW"}}], "severity": [self.CRIT]}
        self.assertEqual(vulndb.severity_of(v), ("low", 9.8))

    def test_unknown_or_non_string_label_falls_back_to_score(self):
        self.assertEqual(vulndb.severity_of({"database_specific": {"severity": "UNKNOWN"}, "severity": [self.MED]}), ("medium", 5.5))
        self.assertEqual(vulndb.severity_of({"database_specific": {"severity": "UNKNOWN"}}), (None, None))
        self.assertEqual(vulndb.severity_of({"database_specific": {"severity": 7}}), (None, None))

    def test_zero_score_is_info(self):
        zero = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}
        self.assertEqual(vulndb.severity_of({"severity": [zero]}), ("info", 0.0))

    def test_missing_severity(self):
        for v in ({}, {"id": "GHSA-x"}, {"severity": None, "database_specific": None, "affected": None},
                  {"severity": [], "affected": []}, {"database_specific": {}}):
            with self.subTest(vuln=v):
                self.assertEqual(vulndb.severity_of(v), (None, None))

    def test_null_score_in_record_does_not_crash(self):
        self.assertEqual(vulndb.severity_of({"severity": [{"type": "CVSS_V3", "score": None}]}), (None, None))
        self.assertEqual(vulndb.severity_of({"severity": [None, "x", {"type": "CVSS_V3", "score": 9.8}], "affected": [None]}),
                         (None, None))

    def test_cvss_v4_only_uses_label(self):
        # CVSS 4.0 is not computed locally: the advisory label wins, otherwise (None, None) sends deps.py to the NVD
        v4 = {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
        self.assertEqual(vulndb.severity_of({"severity": [v4], "database_specific": {"severity": "HIGH"}}), ("high", None))
        self.assertEqual(vulndb.severity_of({"severity": [v4, self.MED]}), ("medium", 5.5))


# --------------------------------------------------------------------------- ordem de versões


class VersionKey(unittest.TestCase):
    def lt(self, a, b):
        return vulndb._vkey(a) < vulndb._vkey(b)

    def test_numeric_not_lexicographic(self):
        self.assertTrue(self.lt("1.9", "1.10"))
        self.assertTrue(self.lt("1.9.9", "1.10.0"))
        self.assertTrue(self.lt("1.9", "1.9.1"))
        self.assertTrue(self.lt("1.99.99", "2.0"))
        self.assertTrue(self.lt("4.17.15", "4.17.19"))
        self.assertEqual(sorted(["1.10.0", "1.2.0", "1.9.0", "v1.3.0", "0.9"], key=vulndb._vkey),
                         ["0.9", "1.2.0", "v1.3.0", "1.9.0", "1.10.0"])

    def test_v_prefix_ignored(self):
        self.assertEqual(vulndb._vkey("v1.2.3"), vulndb._vkey("1.2.3"))
        self.assertEqual(vulndb._vkey("V1.2.3"), vulndb._vkey("1.2.3"))
        self.assertTrue(self.lt("v1.9.0", "1.10.0"))

    def test_prerelease_identifiers_order_among_themselves(self):
        self.assertTrue(self.lt("1.0.0-alpha", "1.0.0-beta"))
        self.assertTrue(self.lt("1.0.0-alpha.1", "1.0.0-alpha.2"))
        self.assertTrue(self.lt("1.0.0-beta.2", "1.0.0-beta.11"))
        self.assertTrue(self.lt("1.0.0-beta.11", "1.0.0-rc.1"))

    def test_go_pseudo_version_below_next_release(self):
        self.assertTrue(self.lt("v0.0.0-20220722155237-a158d28d115b", "v0.1.0"))
        self.assertTrue(self.lt("v0.0.0-20210101000000-abcdef123456", "v0.0.0-20220722155237-a158d28d115b"))

    def test_mixed_parts_do_not_raise(self):
        sorted(["1.0.0", "1.0.x", "1.a", "", "1..2", "1.0+build", "1_0", "latest"], key=vulndb._vkey)

    def test_prerelease_sorts_before_release(self):
        self.assertTrue(self.lt("1.0.0-alpha", "1.0.0"))
        self.assertTrue(self.lt("2.0.0-rc.1", "2.0.0"))
        self.assertTrue(self.lt("1.0rc1", "1.0"))
        self.assertTrue(self.lt("1.0rc1", "1.0.1"))

    def test_pep440_and_semver_full_order(self):
        pep = ["1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.0.1", "1!0.5"]
        self.assertEqual(sorted(reversed(pep), key=vulndb._vkey), pep)
        semver = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
                  "1.0.0-rc.1", "1.0.0", "1.0.1"]
        self.assertEqual(sorted(reversed(semver), key=vulndb._vkey), semver)
        self.assertEqual(vulndb._vkey("1.0"), vulndb._vkey("1.0.0"))
        self.assertEqual(vulndb._vkey("1.0.0+build.7"), vulndb._vkey("1.0.0"))
        self.assertTrue(self.lt("5.2.0.rc1", "5.2.0") and self.lt("5.2.2", "5.2.2.1"))  # RubyGems


# --------------------------------------------------------------------------- versão corrigida


def vuln(*ranges, eco="npm", name="lodash", rtype="SEMVER", extra=()):
    affected = [{"package": {"ecosystem": eco, "name": name},
                 "ranges": [{"type": rtype, "events": list(events)} for events in ranges]}]
    return {"id": "GHSA-test", "affected": affected + list(extra)}


class FixedVersion(unittest.TestCase):
    def test_introduced_zero(self):
        v = vuln([{"introduced": "0"}, {"fixed": "4.17.19"}])
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "4.17.15"), "4.17.19")

    def test_lowest_fix_above_current_across_ranges_and_affected(self):
        v = vuln([{"introduced": "0"}, {"fixed": "4.17.12"}],
                 [{"introduced": "4.17.13"}, {"fixed": "4.17.21"}],
                 [{"introduced": "4.17.14"}, {"fixed": "4.17.19"}],
                 extra=[{"package": {"ecosystem": "npm", "name": "lodash"},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.17.16"}, {"fixed": "4.17.20"}]}]}])
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "4.17.15"), "4.17.19")

    def test_branch_ranges(self):
        v = vuln([{"introduced": "0"}, {"fixed": "1.2.5"}], [{"introduced": "2.0.0"}, {"fixed": "2.0.3"}])
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "1.2.0"), "1.2.5")
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "2.0.1"), "2.0.3")

    def test_same_major_preferred_then_next_major(self):
        v = vuln([{"introduced": "0"}, {"fixed": "1.4.0"}], [{"introduced": "1.5.0"}, {"fixed": "1.6.0"}],
                 [{"introduced": "1.7.0"}, {"fixed": "2.0.0"}])
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "1.5.0"), "1.6.0")
        v = vuln([{"introduced": "0"}, {"fixed": "1.4.0"}], [{"introduced": "1.5.0"}, {"fixed": "3.0.0"}],
                 [{"introduced": "1.5.0"}, {"fixed": "2.1.0"}])
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "1.5.0"), "2.1.0")

    def test_numeric_ordering_of_fixes(self):
        v = vuln([{"introduced": "0"}, {"fixed": "1.10.0"}], [{"introduced": "0"}, {"fixed": "1.9.5"}])
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "1.9.0"), "1.9.5")
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "1.9.6"), "1.10.0")

    def test_go_v_prefix(self):
        v = vuln([{"introduced": "0"}, {"fixed": "1.10.0"}], [{"introduced": "0"}, {"fixed": "1.9.2"}],
                 eco="Go", name="github.com/gin-gonic/gin")
        # OSV stores Go versions without the "v" that go get needs (go get mod@v1.9.2)
        self.assertEqual(vulndb.fixed_version(v, "Go", "github.com/gin-gonic/gin", "v1.9.0"), "v1.9.2")
        self.assertEqual(vulndb.fixed_version(v, "Go", "github.com/gin-gonic/gin", "1.9.0"), "1.9.2")
        self.assertEqual(vulndb.fixed_version(v, "Go", "github.com/gin-gonic/gin", "v1.9.5"), "v1.10.0")
        v = vuln([{"introduced": "0"}, {"fixed": "v1.9.2"}], eco="Go", name="github.com/gin-gonic/gin")
        self.assertEqual(vulndb.fixed_version(v, "Go", "github.com/gin-gonic/gin", "v1.9.0"), "v1.9.2")

    def test_no_fix_available(self):
        cases = [vuln([{"introduced": "0"}]), vuln([{"introduced": "0"}, {"last_affected": "4.17.21"}]),
                 vuln([{"introduced": "0"}, {"fixed": "4.17.10"}]), vuln(), {"id": "x"}, {"affected": None},
                 {"affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": None}]}]
        for v in cases:
            with self.subTest(vuln=v):
                self.assertIsNone(vulndb.fixed_version(v, "npm", "lodash", "4.17.15"))

    def test_only_matching_package_and_ecosystem(self):
        other = [{"package": {"ecosystem": "npm", "name": "underscore"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.16"}]}]}]
        v = vuln([{"introduced": "0"}, {"fixed": "4.17.21"}], extra=other)
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "4.17.15"), "4.17.21")
        self.assertIsNone(vulndb.fixed_version(v, "PyPI", "lodash", "4.17.15"))
        self.assertIsNone(vulndb.fixed_version(v, "npm", "Lodash", "4.17.15"))  # npm names are case-sensitive

    def test_git_ranges_ignored(self):
        v = vuln([{"introduced": "0"}, {"fixed": "a1b2c3d4e5f6"}], rtype="GIT")
        self.assertIsNone(vulndb.fixed_version(v, "npm", "lodash", "4.17.15"))

    def test_ecosystem_suffix_and_pypi_name_normalization(self):
        v = vuln([{"introduced": "0"}, {"fixed": "3.0.10"}], rtype="ECOSYSTEM", eco="PyPI", name="Flask_Cors")
        self.assertEqual(vulndb.fixed_version(v, "PyPI", "flask-cors", "3.0.9"), "3.0.10")
        self.assertEqual(vulndb.fixed_version(v, "PyPI", "flask.cors", "3.0.9"), "3.0.10")
        v = vuln([{"introduced": "0"}, {"fixed": "1.2.3-1"}], rtype="ECOSYSTEM", eco="Debian:11", name="openssl")
        self.assertEqual(vulndb.fixed_version(v, "Debian", "openssl", "1.2.2-1"), "1.2.3-1")

    def test_release_fixes_a_prerelease(self):
        v = vuln([{"introduced": "0"}, {"fixed": "2.0.0"}])
        self.assertEqual(vulndb.fixed_version(v, "npm", "lodash", "2.0.0-beta.1"), "2.0.0")


class AffectsWholeRange(unittest.TestCase):
    """DEP004: the issue at the lowest version of a range is in every version the range allows."""

    def whole(self, v, floor="4.0.0", upper=None, inclusive=False, eco="npm", name="lodash"):
        return vulndb.affects_whole_range(v, eco, name, floor, upper, inclusive)

    def test_fix_inside_the_range_is_a_way_out(self):
        v = vuln([{"introduced": "0"}, {"fixed": "4.17.21"}])
        self.assertFalse(self.whole(v))  # no upper bound: 4.17.21 is allowed
        self.assertFalse(self.whole(v, upper="5.0.0"))
        self.assertTrue(self.whole(v, upper="4.17.21"))  # <4.17.21 leaves the fix out
        self.assertFalse(self.whole(v, upper="4.17.21", inclusive=True))  # <=4.17.21 keeps it
        self.assertTrue(self.whole(v, upper="4.10.0"))

    def test_unfixed_issue_covers_everything(self):
        self.assertTrue(self.whole(vuln([{"introduced": "0"}])))
        self.assertTrue(self.whole(vuln([{"introduced": "0"}, {"fixed": "3.0.0"}], [{"introduced": "4.0.0"}])))

    def test_last_affected_and_limit(self):
        v = vuln([{"introduced": "0"}, {"last_affected": "4.5.0"}])
        self.assertFalse(self.whole(v))  # 4.5.1 and later escape
        self.assertFalse(self.whole(v, floor="4.5.0"))
        self.assertTrue(self.whole(v, upper="4.5.0", inclusive=True))
        self.assertFalse(self.whole(v, upper="5.0.0"))
        self.assertFalse(self.whole(vuln([{"introduced": "0"}, {"limit": "4.2.0"}]), upper="5.0.0"))

    def test_fix_below_the_floor_does_not_count(self):
        v = vuln([{"introduced": "0"}, {"fixed": "3.0.0"}], [{"introduced": "3.5.0"}, {"fixed": "6.0.0"}])
        self.assertTrue(self.whole(v, upper="5.0.0"))
        self.assertFalse(self.whole(v, upper="7.0.0"))

    def test_no_ranges_means_unknown(self):
        for v in ({"id": "x"}, {"affected": None}, {"affected": [None, {"package": None}]},
                  {"affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                                                    "versions": ["4.0.0", "4.0.1"]}]},
                  vuln([{"introduced": "0"}], rtype="GIT"), vuln([{"introduced": "0"}], name="underscore")):
            with self.subTest(vuln=v):
                self.assertFalse(self.whole(v))

    def test_pypi_names_and_versions(self):
        v = vuln([{"introduced": "0"}, {"fixed": "12.3.0"}], rtype="ECOSYSTEM", eco="PyPI", name="pillow")
        self.assertTrue(self.whole(v, floor="10", upper="11", eco="PyPI", name="Pillow"))
        self.assertFalse(self.whole(v, floor="10", eco="PyPI", name="Pillow"))


# --------------------------------------------------------------------------- pacote malicioso

# Recortes dos registros reais do OSV (2026-10-19)
FLATMAP_MAL = {"id": "MAL-2025-20690", "summary": "Malicious code in flatmap-stream (npm)"}
FLATMAP_GHSA1 = {"id": "GHSA-9x64-5r7x-2q53", "summary": "Malicious Package in flatmap-stream",
                 "database_specific": {"cwe_ids": ["CWE-506"], "severity": "CRITICAL"}}
FLATMAP_GHSA2 = {"id": "GHSA-mh6f-8j2x-4483", "summary": "Critical severity vulnerability that affects event-stream and flatmap-stream",
                 "database_specific": {"cwe_ids": ["CWE-506"], "severity": "CRITICAL"}}
CROSSENV = {"id": "GHSA-c2m4-w5hm-vqjw", "aliases": ["CVE-2017-16074"], "summary": "crossenv is malware",
            "database_specific": {"cwe_ids": ["CWE-506"], "severity": "HIGH"}}


class IsMalicious(unittest.TestCase):
    def test_malware_records(self):
        for v in (FLATMAP_MAL, FLATMAP_GHSA1, FLATMAP_GHSA2, CROSSENV,
                  {"id": "GHSA-x", "summary": "Embedded malicious code in rest-client"},
                  {"id": "GHSA-y", "summary": "Malware in ua-parser-js"}):
            with self.subTest(id=v["id"]):
                self.assertTrue(vulndb.is_malicious(v))

    def test_ordinary_vulnerabilities(self):
        for v in ({"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash", "database_specific": {"cwe_ids": ["CWE-1321"]}},
                  {"id": "GHSA-z", "summary": "Arbitrary code execution when parsing a malicious package.json"},
                  {"id": "GHSA-w", "summary": None, "database_specific": None}, {}):
            with self.subTest(vuln=v):
                self.assertFalse(vulndb.is_malicious(v))


class MalwareInDeps(unittest.TestCase):
    """deps.check com o OSV simulado: aviso de malware nunca vira DEP001."""

    def check(self, pkgs, ids, docs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        packages = {"": {"name": "app"}}
        packages.update({f"node_modules/{n}": {"version": v} for n, v in pkgs})
        with open(os.path.join(tmp.name, "package-lock.json"), "w", encoding="utf-8") as fh:
            json.dump({"lockfileVersion": 3, "packages": packages}, fh, indent=2)
        ctx = Context(tmp.name, ["package-lock.json"])
        with mock.patch.object(vulndb, "osv_query", return_value=ids), \
                mock.patch.object(vulndb, "osv_vulns", side_effect=lambda want: {i: docs[i] for i in want}), \
                mock.patch.object(vulndb, "kev", return_value=({}, "2026.10.16")), \
                mock.patch.object(vulndb, "epss", return_value={}), \
                mock.patch.object(vulndb, "nvd_severity", return_value=None):
            return deps.check(ctx)

    def test_github_malware_advisories_fold_into_the_mal_record(self):
        docs = {d["id"]: d for d in (FLATMAP_MAL, FLATMAP_GHSA1, FLATMAP_GHSA2)}
        got = self.check([("flatmap-stream", "0.1.1")], [sorted(docs)], docs)
        self.assertEqual([(f.rule, f.severity) for f in got], [("DEP002", "critical")])
        self.assertEqual(got[0].params["vuln_id"], "MAL-2025-20690")
        self.assertEqual(got[0].params["advisories"], ["MAL-2025-20690", "GHSA-9x64-5r7x-2q53", "GHSA-mh6f-8j2x-4483"])
        self.assertEqual(got[0].refs, ["https://osv.dev/vulnerability/MAL-2025-20690"])

    def test_github_malware_without_mal_record_is_dep002(self):
        lodash = {"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"], "summary": "Prototype Pollution in lodash",
                  "database_specific": {"severity": "HIGH"}}
        docs = {CROSSENV["id"]: CROSSENV, lodash["id"]: lodash}
        got = self.check([("crossenv", "1.0.0"), ("lodash", "4.17.15")], [[CROSSENV["id"]], [lodash["id"]]], docs)
        self.assertEqual([(f.rule, f.params["pkg"]) for f in got], [("DEP002", "crossenv"), ("DEP001", "lodash")])
        self.assertEqual((got[0].params["vuln_id"], got[0].tags), ("GHSA-c2m4-w5hm-vqjw", ["malicious"]))


# --------------------------------------------------------------------------- consultas (fetch_json simulado)


class OsvQuery(unittest.TestCase):
    def test_body_order_and_results(self):
        res = {"results": [{"vulns": [{"id": "GHSA-a", "modified": "x"}, {"id": "CVE-1"}]}, {}]}
        with mock.patch.object(vulndb, "fetch_json", return_value=res) as fj:
            got = vulndb.osv_query([("npm", "lodash", "4.17.15"), ("PyPI", "django", "3.2.0")])
        self.assertEqual(got, [["GHSA-a", "CVE-1"], []])
        (url, body), kw = fj.call_args
        self.assertEqual(url, vulndb.OSV_BATCH)
        self.assertEqual(body, {"queries": [{"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.15"},
                                            {"package": {"ecosystem": "PyPI", "name": "django"}, "version": "3.2.0"}]})
        self.assertEqual(kw, {"ttl": 6 * vulndb.HOUR, "valid": mock.ANY})

    def test_chunks_of_500(self):
        pkgs = [("npm", "p%d" % i, "1.0.0") for i in range(501)]
        with mock.patch.object(vulndb, "fetch_json", side_effect=lambda url, body, ttl, **kw: {"results": [{}] * len(body["queries"])}) as fj:
            got = vulndb.osv_query(pkgs)
        self.assertEqual([len(c.args[1]["queries"]) for c in fj.call_args_list], [500, 1])
        self.assertEqual(len(got), 501)

    def test_empty_input_makes_no_call(self):
        with mock.patch.object(vulndb, "fetch_json") as fj:
            self.assertEqual(vulndb.osv_query([]), [])
        fj.assert_not_called()

    def test_net_error_propagates(self):
        with mock.patch.object(vulndb, "fetch_json", side_effect=NetError("down")):
            with self.assertRaises(NetError):
                vulndb.osv_query([("npm", "a", "1")])


class OsvVulns(unittest.TestCase):
    def test_dedup_and_failures_dropped(self):
        def fake(url, ttl, **kw):
            if url.endswith("/BAD"):
                raise NetError("404")
            if url.endswith("/EMPTY"):
                return {}
            return {"id": url.rsplit("/", 1)[-1]}
        with mock.patch.object(vulndb, "fetch_json", side_effect=fake) as fj:
            got = vulndb.osv_vulns(["GHSA-b", "GHSA-a", "GHSA-b", "BAD", "EMPTY"])
        self.assertEqual(got, {"GHSA-a": {"id": "GHSA-a"}, "GHSA-b": {"id": "GHSA-b"}})
        self.assertEqual(fj.call_count, 4)
        self.assertIn(mock.call(vulndb.OSV_VULN.format("GHSA-a"), ttl=24 * vulndb.HOUR, valid=mock.ANY), fj.call_args_list)


class Kev(unittest.TestCase):
    def test_index_by_cve(self):
        feed = {"catalogVersion": "2026.10.16", "vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
                                                                     {"cveID": "CVE-2020-1", "vendorProject": "X"}]}
        with mock.patch.object(vulndb, "fetch_json", return_value=feed) as fj:
            got, version = vulndb.kev()
        self.assertEqual(version, "2026.10.16")
        self.assertEqual(sorted(got), ["CVE-2020-1", "CVE-2021-44228"])
        self.assertEqual(got["CVE-2021-44228"]["vendorProject"], "Apache")
        fj.assert_called_once_with(vulndb.KEV_URL, ttl=12 * vulndb.HOUR, timeout=60, valid=mock.ANY)

    def test_empty_feed_is_a_failure(self):
        # Catálogo vazio não quer dizer "nada explorado": é resposta errada, e o relatório tem que dizer que a KEV falhou.
        with mock.patch.object(vulndb, "fetch_json", return_value={}):
            with self.assertRaises(NetError):
                vulndb.kev()


class Epss(unittest.TestCase):
    def test_filters_chunks_and_parses(self):
        cves = ["CVE-2021-%04d" % i for i in range(81)] + ["GHSA-xxxx", "PYSEC-1", "CVE-2021-0000"]

        def fake(url, ttl, **kw):
            ids = url.split("cve=", 1)[1].split(",")
            if "CVE-2021-0080" in ids:
                raise NetError("timeout")
            return {"data": [{"cve": c, "epss": "0.%02d" % (int(c[-2:]) % 100), "percentile": "0.5"} for c in ids]}
        with mock.patch.object(vulndb, "fetch_json", side_effect=fake) as fj:
            got = vulndb.epss(cves)
        self.assertEqual(fj.call_count, 2)
        self.assertEqual(len(fj.call_args_list[0].args[0].split("cve=", 1)[1].split(",")), 80)
        self.assertEqual(len(got), 80)  # second chunk failed and is skipped
        self.assertEqual(got["CVE-2021-0042"], (0.42, 0.5))
        self.assertNotIn("CVE-2021-0080", got)

    def test_no_cves_no_call(self):
        with mock.patch.object(vulndb, "fetch_json") as fj:
            self.assertEqual(vulndb.epss(["GHSA-a", "MAL-1"]), {})
        fj.assert_not_called()


class NvdSeverity(unittest.TestCase):
    @staticmethod
    def doc(**metrics):
        return {"vulnerabilities": [{"cve": {"id": "CVE-1", "metrics": metrics}}]}

    def test_prefers_v40_then_v31_then_v30(self):
        m40 = [{"cvssData": {"baseScore": 9.3}}]
        m31 = [{"cvssData": {"baseScore": 7.5}}]
        m30 = [{"cvssData": {"baseScore": 5.0}}]
        cases = [(self.doc(cvssMetricV31=m31, cvssMetricV40=m40, cvssMetricV30=m30), 9.3),
                 (self.doc(cvssMetricV30=m30, cvssMetricV31=m31), 7.5),
                 (self.doc(cvssMetricV30=m30), 5.0),
                 (self.doc(cvssMetricV31=[{"cvssData": {}}, {"cvssData": {"baseScore": "6.1"}}]), 6.1),
                 (self.doc(cvssMetricV2=[{"cvssData": {"baseScore": 10.0}}]), None),
                 ({}, None), ({"vulnerabilities": []}, None)]
        for d, want in cases:
            with self.subTest(doc=d), mock.patch.object(vulndb, "fetch_json", return_value=d):
                self.assertEqual(vulndb.nvd_severity("CVE-1"), want)

    def test_net_error_returns_none(self):
        with mock.patch.object(vulndb, "fetch_json", side_effect=NetError("403")):
            self.assertIsNone(vulndb.nvd_severity("CVE-1"))

    def test_api_key_header_from_env(self):
        with mock.patch.dict(os.environ, {"NVD_API_KEY": "k123"}), \
                mock.patch.object(vulndb, "fetch_json", return_value={}) as fj:
            vulndb.nvd_severity("CVE-2021-44228")
        fj.assert_called_once_with(vulndb.NVD_URL.format("CVE-2021-44228"), ttl=7 * 24 * vulndb.HOUR, headers={"apiKey": "k123"},
                                   valid=mock.ANY)
        with mock.patch.dict(os.environ), mock.patch.object(vulndb, "fetch_json", return_value={}) as fj:
            os.environ.pop("NVD_API_KEY", None)
            vulndb.nvd_severity("CVE-1")
        self.assertIsNone(fj.call_args.kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
