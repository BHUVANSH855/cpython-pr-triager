from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import update_branch_policy


class ParseBranchStatusesTests(unittest.TestCase):
    def test_parses_supported_and_unsupported_versions(self) -> None:
        html = """
        <html>
          <table>
            <tr>
              <th>Branch</th>
              <th>Schedule</th>
              <th>Status</th>
              <th>First release</th>
              <th>End of life</th>
              <th>Release manager</th>
            </tr>
            <tr>
              <td>main</td>
              <td>PEP 826</td>
              <td>feature</td>
              <td>2027-10-06</td>
              <td>2032-10</td>
              <td>Manager</td>
            </tr>
            <tr>
              <td>3.15</td>
              <td>PEP 790</td>
              <td>prerelease</td>
              <td>2026-10-01</td>
              <td>2031-10</td>
              <td>Manager</td>
            </tr>
            <tr>
              <td>3.14</td>
              <td>PEP 745</td>
              <td>bugfix</td>
              <td>2025-10-07</td>
              <td>2030-10</td>
              <td>Manager</td>
            </tr>
            <tr>
              <td>3.12</td>
              <td>PEP 693</td>
              <td>security</td>
              <td>2023-10-02</td>
              <td>2028-10</td>
              <td>Manager</td>
            </tr>
            <tr>
              <td>3.9</td>
              <td>PEP 596</td>
              <td>end of life</td>
              <td>2020-10-05</td>
              <td>2025-10-31</td>
              <td>Manager</td>
            </tr>
          </table>
        </html>
        """

        result = update_branch_policy.parse_branch_statuses(html)

        self.assertEqual(
            result,
            {
                "main": "feature",
                "3.15": "prerelease",
                "3.14": "bugfix",
                "3.12": "security",
                "3.9": "end-of-life",
            },
        )

    def test_ignores_unknown_statuses(self) -> None:
        html = """
        <table>
          <tr>
            <th>Branch</th>
            <th>Schedule</th>
            <th>Status</th>
            <th>First release</th>
            <th>End of life</th>
            <th>Release manager</th>
          </tr>
          <tr>
            <td>main</td>
            <td>PEP 826</td>
            <td>feature</td>
            <td>2027-10-06</td>
            <td>2032-10</td>
            <td>Manager</td>
          </tr>
          <tr>
            <td>3.20</td>
            <td>PEP 999</td>
            <td>future-status</td>
            <td>2030-01-01</td>
            <td>2035-01</td>
            <td>Manager</td>
          </tr>
        </table>
        """

        result = update_branch_policy.parse_branch_statuses(html)

        self.assertEqual(result, {"main": "feature"})

    def test_ignores_non_version_rows(self) -> None:
        html = """
        <table>
          <tr>
            <th>Branch</th>
            <th>Schedule</th>
            <th>Status</th>
            <th>First release</th>
            <th>End of life</th>
            <th>Release manager</th>
          </tr>
          <tr>
            <td>Branch</td>
            <td>Schedule</td>
            <td>Status</td>
            <td>-</td>
            <td>-</td>
            <td>-</td>
          </tr>
          <tr>
            <td>main</td>
            <td>PEP 826</td>
            <td>feature</td>
            <td>2027-10-06</td>
            <td>2032-10</td>
            <td>Manager</td>
          </tr>
          <tr>
            <td>docs</td>
            <td>PEP 000</td>
            <td>bugfix</td>
            <td>-</td>
            <td>-</td>
            <td>Manager</td>
          </tr>
        </table>
        """

        result = update_branch_policy.parse_branch_statuses(html)

        self.assertEqual(result, {"main": "feature"})


class BuildSnapshotTests(unittest.TestCase):
    def test_builds_versioned_snapshot(self) -> None:
        statuses = {
            "main": "feature",
            "3.15": "prerelease",
            "3.14": "bugfix",
        }

        snapshot = update_branch_policy.build_snapshot(
            statuses,
            retrieved_at="2026-09-10T00:00:00Z",
        )

        self.assertEqual(snapshot["schema_version"], 1)
        self.assertEqual(
            snapshot["source"],
            update_branch_policy.SOURCE_URL,
        )
        self.assertEqual(
            snapshot["retrieved_at"],
            "2026-09-10T00:00:00Z",
        )
        self.assertEqual(
            snapshot["statuses"],
            {
                "3.14": "bugfix",
                "3.15": "prerelease",
                "main": "feature",
            },
        )

    def test_empty_statuses_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            update_branch_policy.build_snapshot({})

    def test_invalid_statuses_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            update_branch_policy.build_snapshot(
                {
                    "main": "not-a-real-status",
                }
            )


class WriteSnapshotTests(unittest.TestCase):
    def test_writes_valid_json(self) -> None:
        snapshot = update_branch_policy.build_snapshot(
            {"main": "feature"},
            retrieved_at="2026-09-10T00:00:00Z",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "branch-policy.json"

            update_branch_policy.write_snapshot(output, snapshot)

            self.assertTrue(output.exists())

            payload = json.loads(
                output.read_text(encoding="utf-8")
            )

            self.assertEqual(payload, snapshot)

    def test_creates_parent_directory(self) -> None:
        snapshot = update_branch_policy.build_snapshot(
            {"main": "feature"},
            retrieved_at="2026-09-10T00:00:00Z",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = (
                Path(temp_dir)
                / "nested"
                / "branch-policy.json"
            )

            update_branch_policy.write_snapshot(output, snapshot)

            self.assertTrue(output.exists())


class RefreshTests(unittest.TestCase):
    def test_refresh_fetches_and_writes_snapshot(self) -> None:
        html = """
        <table>
          <tr>
            <th>Branch</th>
            <th>Schedule</th>
            <th>Status</th>
            <th>First release</th>
            <th>End of life</th>
            <th>Release manager</th>
          </tr>
          <tr>
            <td>main</td>
            <td>PEP 826</td>
            <td>feature</td>
            <td>2027-10-06</td>
            <td>2032-10</td>
            <td>Manager</td>
          </tr>
          <tr>
            <td>3.15</td>
            <td>PEP 790</td>
            <td>prerelease</td>
            <td>2026-10-01</td>
            <td>2031-10</td>
            <td>Manager</td>
          </tr>
        </table>
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "branch-policy.json"

            with patch(
                "scripts.update_branch_policy.fetch_source",
                return_value=html,
            ):
                snapshot = update_branch_policy.refresh(output)

            self.assertEqual(
                snapshot["statuses"],
                {
                    "3.15": "prerelease",
                    "main": "feature",
                },
            )
            self.assertTrue(output.exists())

    def test_refresh_refuses_to_write_without_main(self) -> None:
        html = """
        <table>
          <tr>
            <th>Branch</th>
            <th>Schedule</th>
            <th>Status</th>
            <th>First release</th>
            <th>End of life</th>
            <th>Release manager</th>
          </tr>
          <tr>
            <td>3.15</td>
            <td>PEP 790</td>
            <td>prerelease</td>
            <td>2026-10-01</td>
            <td>2031-10</td>
            <td>Manager</td>
          </tr>
        </table>
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "branch-policy.json"

            with patch(
                "scripts.update_branch_policy.fetch_source",
                return_value=html,
            ):
                with self.assertRaises(ValueError):
                    update_branch_policy.refresh(output)

            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()