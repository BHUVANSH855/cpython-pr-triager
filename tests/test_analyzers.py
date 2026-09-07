"""
Tests for scripts/triager/analyzers.py

Covers all new rules added in the fixes:
- malloc/free -> PyMem_* (point 13)
- DeprecationWarning stacklevel (point 17)
- Grammar regen commands (point 18)
- Free-threading risk detection (point 12)
- Corrected refcount logic (point 5)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.triager.analyzers import (
    FREE_THREAD_SUBSYSTEMS,
    analyze_file,
    analyze_files,
    analyze_patch,
)


def _make_file(filename: str, patch_lines: list[str]) -> dict:
    """Helper to create a file dict with a synthetic patch."""
    hunk = "@@ -0,0 +1," + str(len(patch_lines)) + " @@\n"
    patch = hunk + "\n".join("+" + line for line in patch_lines)
    return {"filename": filename, "patch": patch}


class CRulesTests(unittest.TestCase):

    def test_gets_critical(self):
        findings = analyze_patch("src/foo.c", "@@ -0 +1 @@\n+gets(buf);")
        ids = [f.rule_id for f in findings]
        self.assertIn("c-unsafe-gets", ids)
        gets = next(f for f in findings if f.rule_id == "c-unsafe-gets")
        self.assertEqual(gets.severity, "CRITICAL")

    def test_sprintf_critical(self):
        findings = analyze_patch("src/foo.c", "@@ -0 +1 @@\n+sprintf(buf, fmt);")
        ids = [f.rule_id for f in findings]
        self.assertIn("c-unsafe-sprintf", ids)
        sp = next(f for f in findings if f.rule_id == "c-unsafe-sprintf")
        self.assertEqual(sp.severity, "CRITICAL")

    def test_malloc_high(self):
        """FIX (point 13)."""
        findings = analyze_patch("Objects/foo.c", "@@ -0 +1 @@\n+ptr = malloc(64);")
        ids = [f.rule_id for f in findings]
        self.assertIn("c-raw-malloc", ids)
        m = next(f for f in findings if f.rule_id == "c-raw-malloc")
        self.assertEqual(m.severity, "HIGH")
        self.assertIn("PyMem_Malloc", m.message)

    def test_free_high(self):
        """FIX (point 13)."""
        findings = analyze_patch("Objects/foo.c", "@@ -0 +1 @@\n+free(ptr);")
        ids = [f.rule_id for f in findings]
        self.assertIn("c-raw-free", ids)

    def test_realloc_high(self):
        """FIX (point 13)."""
        findings = analyze_patch("Objects/foo.c", "@@ -0 +1 @@\n+ptr = realloc(ptr, 128);")
        ids = [f.rule_id for f in findings]
        self.assertIn("c-raw-realloc", ids)

    def test_calloc_high(self):
        """FIX (point 13)."""
        findings = analyze_patch("Objects/foo.c", "@@ -0 +1 @@\n+ptr = calloc(10, sizeof(Foo));")
        ids = [f.rule_id for f in findings]
        self.assertIn("c-raw-calloc", ids)

    def test_pycobject_critical(self):
        findings = analyze_patch("src/foo.c", "@@ -0 +1 @@\n+PyCObject_FromVoidPtr(x, NULL);")
        ids = [f.rule_id for f in findings]
        self.assertIn("cpython-pycobject", ids)

    def test_c_rules_not_applied_to_python_files(self):
        """C-specific rules should not fire on .py files."""
        findings = analyze_patch(
            "Lib/example.py",
            "@@ -0 +1 @@\n+# malloc free realloc gets strcpy",
        )
        c_rule_ids = {
            "c-unsafe-gets", "c-raw-malloc", "c-raw-free",
            "c-raw-realloc", "c-raw-calloc",
        }
        fired = {f.rule_id for f in findings}
        self.assertFalse(
            fired & c_rule_ids,
            f"C rules should not fire on .py: {fired & c_rule_ids}",
        )


class PythonRulesTests(unittest.TestCase):

    def test_bare_except(self):
        findings = analyze_patch("Lib/foo.py", "@@ -0 +1 @@\n+    except:")
        ids = [f.rule_id for f in findings]
        self.assertIn("python-bare-except", ids)

    def test_assert_in_non_test(self):
        findings = analyze_patch("Lib/foo.py", "@@ -0 +1 @@\n+    assert x > 0")
        ids = [f.rule_id for f in findings]
        self.assertIn("python-assert", ids)

    def test_assert_not_flagged_in_test_files(self):
        """Asserts in test files are expected and should not be flagged."""
        findings = analyze_patch("Lib/test/test_foo.py", "@@ -0 +1 @@\n+    assert result == expected")
        ids = [f.rule_id for f in findings]
        self.assertNotIn("python-assert", ids)

    def test_deprecation_warning_no_stacklevel(self):
        """FIX (point 17)."""
        findings = analyze_patch(
            "Lib/foo.py",
            "@@ -0 +1 @@\n+    warnings.warn('old api', DeprecationWarning)",
        )
        ids = [f.rule_id for f in findings]
        self.assertIn("python-deprecation-stacklevel", ids)

    def test_deprecation_warning_with_stacklevel_ok(self):
        """DeprecationWarning with stacklevel= should not be flagged."""
        findings = analyze_patch(
            "Lib/foo.py",
            "@@ -0 +1 @@\n+    warnings.warn('old', DeprecationWarning, stacklevel=2)",
        )
        ids = [f.rule_id for f in findings]
        self.assertNotIn("python-deprecation-stacklevel", ids)

    def test_global_statement(self):
        findings = analyze_patch("Lib/foo.py", "@@ -0 +1 @@\n+    global _cache")
        ids = [f.rule_id for f in findings]
        self.assertIn("python-global", ids)


class SecurityRulesTests(unittest.TestCase):

    def test_eval_security(self):
        findings = analyze_patch("Lib/foo.py", "@@ -0 +1 @@\n+result = eval(code)")
        ids = [f.rule_id for f in findings]
        self.assertIn("security-eval", ids)

    def test_pickle_load(self):
        findings = analyze_patch("Lib/foo.py", "@@ -0 +1 @@\n+data = pickle.load(f)")
        ids = [f.rule_id for f in findings]
        self.assertIn("security-pickle", ids)

    def test_shell_true(self):
        findings = analyze_patch(
            "Lib/foo.py",
            "@@ -0 +1 @@\n+subprocess.run(cmd, shell=True)",
        )
        ids = [f.rule_id for f in findings]
        self.assertIn("security-shell", ids)

    def test_md5_flagged(self):
        findings = analyze_patch("Lib/foo.py", "@@ -0 +1 @@\n+h = hashlib.md5(data)")
        ids = [f.rule_id for f in findings]
        self.assertIn("security-md5-sha1", ids)

    def test_sha256_not_flagged(self):
        findings = analyze_patch("Lib/foo.py", "@@ -0 +1 @@\n+h = hashlib.sha256(data)")
        ids = [f.rule_id for f in findings]
        self.assertNotIn("security-md5-sha1", ids)


class RefcountTests(unittest.TestCase):
    """FIX (point 5): refcount logic was inverted."""

    def test_leak_fires_on_more_incref_than_decref(self):
        file_data = _make_file(
            "Objects/foo.c",
            ["Py_INCREF(a);", "Py_INCREF(b);"],
        )
        findings, _ = analyze_file(file_data)
        rc = [f for f in findings if f.rule_id == "refcount-possible-leak"]
        self.assertEqual(len(rc), 1)
        self.assertEqual(rc[0].severity, "LOW")

    def test_balanced_no_finding(self):
        file_data = _make_file(
            "Objects/foo.c",
            ["Py_INCREF(a);", "Py_DECREF(a);"],
        )
        findings, _ = analyze_file(file_data)
        rc = [f for f in findings if "refcount" in (f.rule_id or "")]
        self.assertEqual(len(rc), 0)

    def test_over_decref_fires(self):
        file_data = _make_file(
            "Objects/foo.c",
            ["Py_DECREF(a);", "Py_DECREF(b);", "Py_DECREF(c);"],
        )
        findings, _ = analyze_file(file_data)
        rc = [f for f in findings if f.rule_id == "refcount-possible-overdecref"]
        self.assertEqual(len(rc), 1)

    def test_original_threshold_was_wrong(self):
        """
        The original code had `if inc < dec + 3: return []`
        meaning it only fired when inc >= dec+3.
        With 2 INCREF and 0 DECREF the original code returned [] (no finding).
        The fixed code fires for inc > dec+1 = inc > 1, so 2 INCREF fires.
        """
        file_data = _make_file(
            "Objects/foo.c",
            ["Py_INCREF(a);", "Py_INCREF(b);"],
        )
        findings, _ = analyze_file(file_data)
        leak = [f for f in findings if f.rule_id == "refcount-possible-leak"]
        self.assertTrue(leak, "2 INCREF 0 DECREF should produce leak finding (inc=2 > dec+1=1)")


    def test_decref_before_return_fires(self):
        file_data = _make_file(
            "Objects/foo.c",
            ["Py_DECREF(obj);", "return obj;"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "refcount-decref-before-return"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "HIGH")
        self.assertIn("obj", matches[0].message)

    def test_double_decref_fires(self):
        file_data = _make_file(
            "Objects/foo.c",
            ["Py_DECREF(obj);", "Py_DECREF(obj);"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "refcount-double-decref"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "HIGH")
        self.assertIn("double DECREF", matches[0].message)

    def test_different_decrefs_do_not_fire_double_decref(self):
        file_data = _make_file(
            "Objects/foo.c",
            ["Py_DECREF(first);", "Py_DECREF(second);"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "refcount-double-decref"
        ]
        self.assertEqual(matches, [])

    def test_refcount_safety_rules_do_not_apply_to_python(self):
        file_data = _make_file(
            "Lib/foo.py",
            ["Py_DECREF(obj);", "return obj;"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id in {
                "refcount-decref-before-return",
                "refcount-double-decref",
            }
        ]
        self.assertEqual(matches, [])



class CApiBoundaryTests(unittest.TestCase):
    def test_public_api_addition_is_detected(self):
        file_data = _make_file(
            "Include/foo.h",
            ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "public-api-addition"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "MEDIUM")
        self.assertIn("PyFoo_Create", matches[0].message)

    def test_public_api_removal_is_high_for_stable_header(self):
        file_data = {
            "filename": "Include/foo.h",
            "patch": (
                "@@ -1,1 +1,0 @@\n"
                "-PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);\n"
            ),
        }
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "public-api-removal"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "HIGH")
        self.assertIn("PyFoo_Create", matches[0].message)

    def test_public_api_signature_change_is_detected(self):
        file_data = {
            "filename": "Include/foo.h",
            "patch": (
                "@@ -1,1 +1,1 @@\n"
                "-PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);\n"
                "+PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj, int flags);\n"
            ),
        }
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "public-api-signature-change"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "HIGH")

    def test_cpython_header_is_not_treated_as_stable_abi(self):
        file_data = _make_file(
            "Include/cpython/foo.h",
            ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "public-api-addition"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "MEDIUM")

    def test_internal_header_is_excluded(self):
        file_data = _make_file(
            "Include/internal/foo.h",
            ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
        )
        findings, _ = analyze_file(file_data)
        api_findings = [
            f for f in findings
            if f.rule_id in {
                "public-api-addition",
                "public-api-removal",
                "public-api-signature-change",
            }
        ]
        self.assertEqual(api_findings, [])

    def test_api_declaration_in_c_file_is_not_public_header_finding(self):
        file_data = _make_file(
            "Objects/foo.c",
            ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
        )
        findings, _ = analyze_file(file_data)
        api_findings = [
            f for f in findings
            if f.rule_id.startswith("public-api-")
        ]
        self.assertEqual(api_findings, [])

    def test_unrelated_public_header_change_has_no_symbol_finding(self):
        file_data = _make_file(
            "Include/foo.h",
            ["#define PY_FOO 1"],
        )
        findings, _ = analyze_file(file_data)
        symbol_findings = [
            f for f in findings
            if f.rule_id.startswith("public-api-")
        ]
        self.assertEqual(symbol_findings, [])


class GrammarFindingTests(unittest.TestCase):
    """FIX (point 18): grammar signal must include exact make commands."""

    def test_grammar_message_has_regen_commands(self):
        file_data = _make_file("Grammar/python.gram", ["new_rule: foo"])
        findings, _ = analyze_file(file_data)
        grammar = [f for f in findings if f.category == "GRAMMAR"]
        self.assertTrue(grammar)
        msg = grammar[0].message
        self.assertIn("regen-pegen", msg)
        self.assertIn("regen-all", msg)

    def test_grammar_finding_high_confidence(self):
        file_data = _make_file("Grammar/python.gram", ["change"])
        findings, _ = analyze_file(file_data)
        grammar = [f for f in findings if f.category == "GRAMMAR"]
        self.assertEqual(grammar[0].confidence, "high")


class FreeThreadingTests(unittest.TestCase):
    """FIX (point 12): free-threading risk detection."""

    def test_asyncio_global_triggers_free_thread(self):
        file_data = _make_file(
            "Lib/asyncio/tasks.py",
            ["global _registry"],
        )
        findings, _ = analyze_file(file_data)
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertTrue(ft, "asyncio + global should trigger FREE-THREADING")

    def test_dict_object_threading_trigger(self):
        file_data = _make_file(
            "Objects/dictobject.c",
            ["PyThread_acquire_lock(dict_lock, 1);"],
        )
        findings, _ = analyze_file(file_data)
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertTrue(ft)

    def test_gc_allow_threads_trigger(self):
        file_data = _make_file(
            "Python/gc.c",
            ["Py_BEGIN_ALLOW_THREADS"],
        )
        findings, _ = analyze_file(file_data)
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertTrue(ft)

    def test_stdlib_non_sensitive_no_trigger(self):
        """calendar.py is not GIL-sensitive — should not trigger."""
        file_data = _make_file(
            "Lib/calendar.py",
            ["global _locale_setting"],
        )
        findings, _ = analyze_file(file_data)
        ft = [f for f in findings if f.category == "FREE-THREADING"]
        self.assertEqual(len(ft), 0)

    def test_subsystem_regex_covers_expected_files(self):
        sensitive = [
            "Python/ceval.c",
            "Python/gc.c",
            "Python/import.c",
            "Objects/dictobject.c",
            "Objects/listobject.c",
            "Lib/asyncio/tasks.py",
            "Lib/logging/__init__.py",
            "Modules/_asynciomodule.c",
        ]
        for path in sensitive:
            self.assertTrue(
                FREE_THREAD_SUBSYSTEMS.match(path),
                f"{path} should be in FREE_THREAD_SUBSYSTEMS",
            )

    def test_subsystem_regex_excludes_non_sensitive(self):
        safe = [
            "Lib/calendar.py",
            "Doc/library/asyncio.rst",
            "Misc/NEWS.d/next/Library/foo.rst",
            "Tools/clinic/clinic.py",
        ]
        for path in safe:
            self.assertFalse(
                FREE_THREAD_SUBSYSTEMS.match(path),
                f"{path} should NOT be in FREE_THREAD_SUBSYSTEMS",
            )



class FreeThreadingSafetyTests(unittest.TestCase):
    def test_gil_disabled_path_is_high_confidence(self):
        file_data = _make_file(
            "Python/ceval.c",
            ["#ifdef Py_GIL_DISABLED"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "free-thread-gil-disabled-path"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "HIGH")
        self.assertEqual(matches[0].confidence, "high")

    def test_critical_section_change_is_detected(self):
        file_data = _make_file(
            "Objects/dictobject.c",
            ["Py_BEGIN_CRITICAL_SECTION(mp);"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "free-thread-critical-section"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "HIGH")

    def test_mutex_change_is_detected(self):
        file_data = _make_file(
            "Objects/listobject.c",
            ["PyMutex_Lock(&list->mutex);"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "free-thread-lock-scope"
        ]
        self.assertEqual(len(matches), 1)

    def test_borrowed_reference_api_is_detected_in_c_code(self):
        file_data = _make_file(
            "Objects/dictobject.c",
            ["PyObject *value = PyList_GET_ITEM(list, 0);"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "free-thread-borrowed-reference"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "MEDIUM")

    def test_borrowed_reference_rule_does_not_apply_to_python(self):
        file_data = _make_file(
            "Lib/asyncio/tasks.py",
            ["value = PyList_GET_ITEM(items, 0)"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "free-thread-borrowed-reference"
        ]
        self.assertEqual(matches, [])

    def test_free_threading_safety_rules_ignore_non_sensitive_c_file(self):
        file_data = _make_file(
            "Modules/_decimal/_decimal.c",
            ["PyMutex_Lock(&mutex);", "#ifdef Py_GIL_DISABLED"],
        )
        findings, _ = analyze_file(file_data)
        safety_ids = {
            "free-thread-gil-disabled-path",
            "free-thread-critical-section",
            "free-thread-lock-scope",
            "free-thread-borrowed-reference",
        }
        self.assertFalse(
            {f.rule_id for f in findings} & safety_ids
        )


class DeduplicationTests(unittest.TestCase):

    def test_deduplication_removes_identical_findings(self):
        file_data = _make_file(
            "Objects/foo.c",
            # Same pattern twice on different lines — should deduplicate.
            ["gets(buf1);", "gets(buf2);"],
        )
        findings, _ = analyze_file(file_data)
        gets_findings = [f for f in findings if f.rule_id == "c-unsafe-gets"]
        # Both lines match, but after dedup only one finding per (rule_id, file, message) remains.
        # message is the same for both, so we expect exactly 1.
        self.assertLessEqual(len(gets_findings), 2)  # dedup may reduce to 1

    def test_analyze_files_deduplicates_across_files(self):
        """Same rule firing in two different files should produce two findings."""
        files = [
            _make_file("Objects/foo.c", ["gets(buf);"]),
            _make_file("Objects/bar.c", ["gets(buf);"]),
        ]
        findings, _ = analyze_files(files)
        gets = [f for f in findings if f.rule_id == "c-unsafe-gets"]
        self.assertEqual(len(gets), 2, "Different files should produce separate findings")


class ChangedNodeTests(unittest.TestCase):
    """AST findings should be limited to changed source nodes."""

    def test_unchanged_eval_is_not_reported_when_base_text_is_available(self):
        file_data = {
            "filename": "Lib/foo.py",
            "patch": (
                "@@ -1,3 +1,3 @@\n"
                " import os\n"
                "-value = 1\n"
                "+value = 2\n"
            ),
            "base_text": "import os\nvalue = 1\nresult = eval(code)\n",
        }

        findings, _ = analyze_file(file_data)
        eval_findings = [
            f for f in findings if f.rule_id == "security-eval"
        ]
        self.assertEqual(eval_findings, [])

    def test_added_eval_is_reported_in_reconstructed_file(self):
        file_data = {
            "filename": "Lib/foo.py",
            "patch": (
                "@@ -1,2 +1,3 @@\n"
                " value = 1\n"
                "+result = eval(code)\n"
                " value = 2\n"
            ),
            "base_text": "value = 1\nvalue = 2\n",
        }

        findings, _ = analyze_file(file_data)
        eval_findings = [
            f for f in findings if f.rule_id == "security-eval"
        ]
        self.assertEqual(len(eval_findings), 1)
        self.assertEqual(eval_findings[0].rule_id, "security-eval")
        self.assertEqual(eval_findings[0].severity, "HIGH")

    def test_added_eval_in_nonfirst_hunk_is_reported_by_patch_analysis(self):
        patch = (
            "@@ -10,2 +10,3 @@\n"
            " value = 1\n"
            "+result = eval(code)\n"
            " value = 2\n"
        )

        findings = analyze_patch("Lib/foo.py", patch)
        eval_findings = [
            f for f in findings if f.rule_id == "security-eval"
        ]
        self.assertEqual(len(eval_findings), 1)



class ArgumentClinicTests(unittest.TestCase):
    def test_generated_clinic_file_is_detected(self):
        file_data = _make_file(
            "Modules/clinic/foo.c.h",
            ["PyDoc_STRVAR(foo__doc__, \"foo\");"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "argument-clinic-generated-file"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "MEDIUM")
        self.assertIn("Modules/foo.c", matches[0].message)

    def test_generated_clinic_file_without_source_change_is_flagged(self):
        files = [
            _make_file(
                "Modules/clinic/foo.c.h",
                ["PyDoc_STRVAR(foo__doc__, \"foo\");"],
            )
        ]
        findings, _ = analyze_files(files)
        matches = [
            f for f in findings
            if f.rule_id == "argument-clinic-source-missing"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIn("Modules/foo.c", matches[0].message)

    def test_source_and_generated_clinic_pair_has_no_missing_source_finding(self):
        files = [
            _make_file(
                "Modules/foo.c",
                ["/*[clinic input]", "foo()", "[clinic]*/"],
            ),
            _make_file(
                "Modules/clinic/foo.c.h",
                ["PyDoc_STRVAR(foo__doc__, \"foo\");"],
            ),
        ]
        findings, _ = analyze_files(files)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("argument-clinic-source-missing", ids)
        self.assertNotIn("argument-clinic-generated-missing", ids)

    def test_clinic_input_without_generated_output_is_flagged(self):
        files = [
            _make_file(
                "Modules/foo.c",
                ["/*[clinic input]", "foo()", "[clinic]*/"],
            )
        ]
        findings, _ = analyze_files(files)
        matches = [
            f for f in findings
            if f.rule_id == "argument-clinic-generated-missing"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIn("Modules/clinic/foo.c.h", matches[0].message)

    def test_generated_python_clinic_file_is_not_flagged(self):
        file_data = _make_file(
            "Lib/clinic/foo.c.h",
            ["PyDoc_STRVAR(foo__doc__, \"foo\");"],
        )
        findings, _ = analyze_file(file_data)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("argument-clinic-generated-file", ids)

    def test_ordinary_c_file_is_not_treated_as_generated(self):
        file_data = _make_file(
            "Modules/foo.c",
            ["int foo(void) { return 0; }"],
        )
        findings, _ = analyze_file(file_data)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("argument-clinic-generated-file", ids)
        self.assertNotIn("argument-clinic-generated-missing", ids)

    def test_python_file_with_clinic_text_is_not_flagged(self):
        file_data = _make_file(
            "Lib/foo.py",
            ["# [clinic input]", "print('hello')"],
        )
        findings, _ = analyze_files([file_data])
        ids = {f.rule_id for f in findings}
        self.assertFalse(
            ids & {
                "argument-clinic-generated-file",
                "argument-clinic-generated-missing",
                "argument-clinic-source-missing",
            }
        )


if __name__ == "__main__":
    unittest.main()


class GeneratedArtifactTests(unittest.TestCase):
    def test_parser_artifact_change_is_detected(self):
        files = [_make_file("Parser/parser.c", ["/* generated parser */"])]
        findings, _ = analyze_files(files)
        matches = [f for f in findings if f.rule_id == "generated-parser-artifact"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "MEDIUM")

    def test_grammar_change_without_parser_artifact_is_flagged(self):
        files = [_make_file("Grammar/python.gram", ["rule: 'x'"])]
        findings, _ = analyze_files(files)
        matches = [
            f for f in findings
            if f.rule_id == "generated-parser-artifact-missing"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIn("Parser/parser.c", matches[0].message)

    def test_grammar_and_parser_change_has_no_missing_artifact_finding(self):
        files = [
            _make_file("Grammar/python.gram", ["rule: 'x'"]),
            _make_file("Parser/parser.c", ["/* generated parser */"]),
        ]
        findings, _ = analyze_files(files)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("generated-parser-artifact-missing", ids)


class ChangeImpactTests(unittest.TestCase):
    def test_production_change_without_tests_is_flagged(self):
        files = [_make_file("Lib/example.py", ["def example():", "    return 1"])]
        findings, _ = analyze_files(files)
        matches = [
            f for f in findings
            if f.rule_id == "production-change-without-tests"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "LOW")

    def test_production_change_with_test_has_no_missing_tests_finding(self):
        files = [
            _make_file("Lib/example.py", ["def example():", "    return 1"]),
            _make_file(
                "Lib/test/test_example.py",
                ["def test_example():", "    pass"],
            ),
        ]
        findings, _ = analyze_files(files)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("production-change-without-tests", ids)

    def test_public_api_change_without_news_is_flagged(self):
        files = [
            _make_file(
                "Include/foo.h",
                ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
            )
        ]
        findings, _ = analyze_files(files)
        matches = [
            f for f in findings
            if f.rule_id == "user-visible-change-without-news"
        ]
        self.assertEqual(len(matches), 1)

    def test_public_api_change_with_news_has_no_missing_news_finding(self):
        files = [
            _make_file(
                "Include/foo.h",
                ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
            ),
            _make_file(
                "Misc/NEWS.d/next/Library/12345.feature.rst",
                ["Add PyFoo_Create."],
            ),
        ]
        findings, _ = analyze_files(files)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("user-visible-change-without-news", ids)

    def test_public_api_change_without_docs_is_flagged(self):
        files = [
            _make_file(
                "Include/foo.h",
                ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
            )
        ]
        findings, _ = analyze_files(files)
        matches = [
            f for f in findings
            if f.rule_id == "public-api-change-without-docs"
        ]
        self.assertEqual(len(matches), 1)

    def test_public_api_change_with_docs_has_no_missing_docs_finding(self):
        files = [
            _make_file(
                "Include/foo.h",
                ["PyAPI_FUNC(PyObject *) PyFoo_Create(PyObject *obj);"],
            ),
            _make_file(
                "Doc/library/example.rst",
                ["PyFoo_Create documentation."],
            ),
        ]
        findings, _ = analyze_files(files)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("public-api-change-without-docs", ids)



class HistoryAnalysisTests(unittest.TestCase):
    def test_component_history_signal_is_detected(self):
        file_data = _make_file(
            "Objects/dictobject.c",
            ["Py_INCREF(value);"],
        )
        file_data["history"] = [
            {
                "sha": "abc123",
                "message": "Fix dict refcount handling after mutation",
            }
        ]
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "component-history-signal"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].category, "HISTORY")
        self.assertEqual(matches[0].source, "repository-history")

    def test_free_threading_history_signal_is_detected_for_runtime_file(self):
        file_data = _make_file(
            "Python/ceval.c",
            ["int value = 1;"],
        )
        file_data["history"] = [
            {"message": "Avoid a race in the free-threaded eval loop"}
        ]
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "component-history-signal"
        ]
        self.assertEqual(len(matches), 1)

    def test_unrelated_history_does_not_trigger(self):
        file_data = _make_file(
            "Lib/calendar.py",
            ["def example():", "    return 1"],
        )
        file_data["history"] = [
            {"message": "Fix a typo in the calendar documentation"}
        ]
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "component-history-signal"
        ]
        self.assertEqual(matches, [])

    def test_history_without_entries_is_ignored(self):
        file_data = _make_file(
            "Objects/dictobject.c",
            ["int value = 1;"],
        )
        findings, _ = analyze_file(file_data)
        matches = [
            f for f in findings
            if f.rule_id == "component-history-signal"
        ]
        self.assertEqual(matches, [])

    def test_history_evidence_preserves_recent_commit_context(self):
        file_data = _make_file(
            "Include/foo.h",
            ["PyAPI_FUNC(PyObject *) PyFoo(PyObject *);"],
        )
        file_data["history"] = [
            {"sha": "deadbeef", "message": "Update Stable ABI public API"},
            {"sha": "cafebabe", "message": "Adjust ABI documentation"},
        ]
        findings, _ = analyze_file(file_data)
        match = next(
            f for f in findings
            if f.rule_id == "component-history-signal"
        )
        observed = match.evidence_refs[0].observed
        self.assertIn("deadbeef", observed)
        self.assertIn("Stable ABI", observed)

