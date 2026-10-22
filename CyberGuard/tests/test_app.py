import unittest
from detector import analyze_text

class CyberGuardTests(unittest.TestCase):
    def test_detects_repeated_failures(self):
        sample = """Oct 21 09:12:01 host sshd[1]: Failed password for admin from 203.0.113.9 port 1001 ssh2
Oct 21 09:12:02 host sshd[2]: Failed password for admin from 203.0.113.9 port 1002 ssh2
Oct 21 09:12:03 host sshd[3]: Failed password for root from 203.0.113.9 port 1003 ssh2"""
        result = analyze_text(sample)
        self.assertEqual(result["failed"], 3)
        self.assertTrue(any(a["title"] == "Repeated failed logins" for a in result["alerts"]))

    def test_detects_success_after_failures(self):
        sample = """Oct 21 09:12:01 host sshd[1]: Failed password for admin from 203.0.113.9 port 1001 ssh2
Oct 21 09:12:02 host sshd[2]: Failed password for admin from 203.0.113.9 port 1002 ssh2
Oct 21 09:12:03 host sshd[3]: Failed password for admin from 203.0.113.9 port 1003 ssh2
Oct 21 09:12:04 host sshd[4]: Accepted password for admin from 203.0.113.9 port 1004 ssh2"""
        result = analyze_text(sample)
        self.assertTrue(any(a["title"] == "Success after repeated failures" for a in result["alerts"]))

    def test_ignores_unrecognized_lines(self):
        result = analyze_text("hello world\\nnot a log")
        self.assertEqual(result["recognized"], 0)
        self.assertEqual(result["failed"], 0)

if __name__ == "__main__":
    unittest.main()
