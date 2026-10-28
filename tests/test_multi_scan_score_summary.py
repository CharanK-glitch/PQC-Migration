import unittest

from server import multi_scan_score_summary


class MultiScanScoreSummaryTests(unittest.TestCase):
    def test_averages_completed_repository_scores(self):
        summary = multi_scan_score_summary([
            {"status": "completed", "score": 41},
            {"status": "completed", "score": 46},
        ])

        self.assertEqual(summary, {
            "score": 44,
            "pqr_score": 44,
            "grade": "D",
            "label": "Major PQC Deficiencies",
        })

    def test_ignores_failed_repositories(self):
        summary = multi_scan_score_summary([
            {"status": "completed", "score": 70},
            {"status": "failed", "error": "clone failed"},
        ])

        self.assertEqual(summary["score"], 70)
        self.assertEqual(summary["pqr_score"], 70)
        self.assertEqual(summary["grade"], "B")

    def test_returns_no_score_when_no_repository_completed(self):
        self.assertEqual(multi_scan_score_summary([
            {"status": "failed", "error": "clone failed"},
        ]), {
            "score": None,
            "pqr_score": None,
            "grade": None,
            "label": None,
        })


if __name__ == "__main__":
    unittest.main()
