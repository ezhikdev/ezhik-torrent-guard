import unittest

import _paths  # noqa: F401
from ezhik_panel.acme import challenge_name
from ezhik_panel.certificates import CertError, analyze, covers, normalize_domains


class DomainTests(unittest.TestCase):
    def test_wildcards_any_depth(self):
        domains = normalize_domains(["*.domain.com", "*.test.domain.com", "*.sub.test.domain.com", "Domain.com."])
        self.assertEqual(domains, ["*.domain.com", "*.test.domain.com", "*.sub.test.domain.com", "domain.com"])

    def test_challenge_record_names(self):
        self.assertEqual(challenge_name("*.domain.com"), "_acme-challenge.domain.com")
        self.assertEqual(challenge_name("domain.com"), "_acme-challenge.domain.com")
        self.assertEqual(challenge_name("*.sub.test.domain.com"), "_acme-challenge.sub.test.domain.com")

    def test_wildcard_coverage_rules(self):
        names = {"*.domain.com"}
        self.assertTrue(covers(names, "a.domain.com"))
        self.assertFalse(covers(names, "domain.com"))
        self.assertFalse(covers(names, "test.sub.domain.com"))
        self.assertTrue(covers({"*.sub.domain.com"}, "test.sub.domain.com"))

    def test_hints_suggest_apex(self):
        hints = analyze(["*.domain.com"])
        self.assertTrue(any(h.get("suggest") == "domain.com" for h in hints))

    def test_invalid_names(self):
        for bad in ("*.com", "a.*.domain.com", "**.domain.com", "-bad.domain.com", "domain", "1.2.3.4"):
            with self.assertRaises(CertError, msg=bad):
                normalize_domains([bad])

    def test_idn_is_punycoded(self):
        self.assertEqual(normalize_domains(["пример.рф"]), ["xn--e1afmkfd.xn--p1ai"])

    def test_separators(self):
        self.assertEqual(normalize_domains(["a.example.com, b.example.com\n*.example.com"]),
                         ["a.example.com", "b.example.com", "*.example.com"])


if __name__ == "__main__":
    unittest.main()
