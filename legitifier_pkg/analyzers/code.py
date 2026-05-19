from __future__ import annotations

from typing import Any

from legitifier_pkg.analyzers.base import BaseAnalyzer, analyzer_for
from legitifier_pkg.core.models import HeuristicConfig, HeuristicResult


@analyzer_for("code_quality")
class CodeAnalyzer(BaseAnalyzer):
    def analyze(self, config: HeuristicConfig, data: dict[str, Any]) -> HeuristicResult:
        handler = getattr(self, f"_handle_{config.id}", self._handle_unknown)
        return handler(config, data)

    def _handle_api_disguised_as_local(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        snippets: list[dict[str, str]] = data.get("code_snippets", [])
        readme: str = data.get("readme", "")
        t = config.thresholds

        api_patterns: list[str] = t.get("api_patterns", [])
        local_claim_patterns: list[str] = t.get("local_claim_patterns", [])

        all_code = "\n".join(s["content"] for s in snippets)
        readme_lower = readme.lower()

        api_matches = [p for p in api_patterns if p.lower() in all_code.lower()]
        local_claims = [p for p in local_claim_patterns if p.lower() in readme_lower]

        triggered = bool(api_matches) and bool(local_claims)
        context = {
            "api_matches": ", ".join(api_matches[:3]),  # truncate for readability
            "local_claims": ", ".join(local_claims[:3]),
        }

        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data={
                "api_matches": api_matches,
                "local_claims": local_claims,
                "files_scanned": len(snippets),
            },
        )

    def _handle_unknown(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        return self._clean_result(config)

    def _clean_result(self, config: HeuristicConfig) -> HeuristicResult:
        return HeuristicResult(
            heuristic_id=config.id,
            score=config.scoring.score_if_clean,
            triggered=False,
            evidence="No signal detected.",
            severity=config.severity,
        )

    def _handle_hardcoded_secrets(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        snippets: list[dict] = data.get("code_snippets", [])
        t = config.thresholds
        secret_patterns: list[str] = t.get("secret_patterns", [])
        placeholder_patterns: list[str] = t.get("placeholder_patterns", [])

        all_code = "\n".join(s["content"] for s in snippets)

        secret_matches = []
        for pattern in secret_patterns:
            if pattern.lower() in all_code.lower():
                # Check it's not a placeholder
                idx = all_code.lower().find(pattern.lower())
                surrounding = all_code[max(0, idx - 10) : idx + len(pattern) + 40]
                if not any(
                    ph.lower() in surrounding.lower() for ph in placeholder_patterns
                ):
                    secret_matches.append(pattern)

        triggered = bool(secret_matches)
        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        context = {"secret_matches": ", ".join(secret_matches[:3])}
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data={"secret_matches": secret_matches, "files_scanned": len(snippets)},
        )

    def _handle_requirements_chaos(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        snippets: list[dict] = data.get("code_snippets", [])
        req_files = [
            s
            for s in snippets
            if "requirements" in s["path"].lower() and s["path"].endswith(".txt")
        ]

        if not req_files:
            return self._clean_result(config)

        import re
        from collections import Counter

        packages: list[str] = []
        for req in req_files:
            for line in req["content"].splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg = re.split(r"[=<>!~\[]", line)[0].strip().lower()
                    if pkg:
                        packages.append(pkg)

        counts = Counter(packages)
        duplicates = [pkg for pkg, count in counts.items() if count > 1]
        min_dup = config.thresholds.get("min_duplicate_packages", 1)
        triggered = len(duplicates) >= min_dup

        context = {
            "duplicate_count": len(duplicates),
            "duplicates": ", ".join(duplicates[:5]),
        }
        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data={"duplicates": duplicates},
        )

    def _handle_test_coverage_signals(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        snippets: list[dict] = data.get("code_snippets", [])
        readme: str = (data.get("readme") or "").lower()
        t = config.thresholds

        min_source_files = t.get("min_source_files", 3)

        # Classify files
        test_files = [
            s
            for s in snippets
            if any(
                s["path"].startswith(p) or f"/{p}" in s["path"]
                for p in ("test", "tests", "spec", "__test__")
            )
            or s["path"].split("/")[-1].startswith("test_")
            or s["path"].split("/")[-1].endswith("_test.py")
        ]
        source_files = [
            s
            for s in snippets
            if s["path"].endswith((".py", ".js", ".ts", ".go", ".rs", ".java"))
            and not any(s["path"].startswith(p) for p in ("test", "tests"))
        ]

        n_tests = len(test_files)
        n_source = len(source_files)
        min_ratio = t.get("min_test_to_source_ratio", 0.05)
        ratio = n_tests / n_source if n_source > 0 else 1.0

        # Check for empty test patterns
        empty_patterns: list[str] = t.get("empty_test_patterns", [])
        all_test_content = "\n".join(s["content"] for s in test_files)
        empty_matches = [p for p in empty_patterns if p in all_test_content]

        # Check for false coverage claims — only meaningful if we have source files
        badge_patterns: list[str] = t.get("coverage_badge_patterns", [])
        badge_matches = [p for p in badge_patterns if p in readme]
        false_coverage_claim = (
            bool(badge_matches) and n_tests == 0 and n_source >= min_source_files
        )

        triggered = (
            (n_source > 3 and ratio < min_ratio)  # source files but almost no tests
            or (bool(empty_matches) and n_tests > 0)  # tests that test nothing
            or false_coverage_claim  # claims high coverage but no test files
        )

        context = {
            "test_files": n_tests,
            "source_files": n_source,
            "ratio": round(ratio, 2),
            "empty_note": f" — empty test patterns: {', '.join(empty_matches[:2])}"
            if empty_matches
            else "",
            "badge_note": " — coverage badge claimed but no tests found"
            if false_coverage_claim
            else "",
        }
        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data={
                "test_files": n_tests,
                "source_files": n_source,
                "ratio": round(ratio, 2),
                "empty_matches": empty_matches,
                "false_coverage_claim": false_coverage_claim,
            },
        )

    def _handle_documentation_quality(
        self, config: HeuristicConfig, data: dict[str, Any]
    ) -> HeuristicResult:
        snippets: list[dict] = data.get("code_snippets", [])
        readme: str = data.get("readme") or ""
        t = config.thresholds

        min_readme_len = t.get("min_readme_length", 500)
        min_comment_ratio = t.get("min_comment_ratio", 0.03)
        min_sections = t.get("min_readme_sections", 2)
        min_source_files = t.get("min_source_files", 3)

        source_files = [
            s
            for s in snippets
            if s["path"].endswith((".py", ".js", ".ts", ".go", ".rs", ".java"))
            and not any(
                p in s["path"] for p in ("test_", "_test.", "/tests/", "/test/")
            )
        ]

        signals = []

        # README length check
        readme_length = len(readme.strip())
        readme_too_short = readme_length < min_readme_len
        if readme_too_short:
            signals.append("short_readme")

        # README sections check
        import re

        sections = len(re.findall(r"^#{1,3}\s+\w+|^\*\*\w+", readme, re.MULTILINE))
        readme_no_structure = sections < min_sections
        if readme_no_structure and readme_length > 100:
            signals.append("no_structure")

        # Comment/docstring ratio in source files
        comment_ratio = 1.0  # default clean if no files
        if len(source_files) >= min_source_files:
            total_lines = 0
            comment_lines = 0
            for s in source_files:
                lines = s["content"].splitlines()
                total_lines += len(lines)
                for line in lines:
                    stripped = line.strip()
                    if (
                        stripped.startswith("#")
                        or stripped.startswith("//")
                        or stripped.startswith("/*")
                        or stripped.startswith("*")
                        or stripped.startswith('"""')
                        or stripped.startswith("'''")
                    ):
                        comment_lines += 1
            comment_ratio = comment_lines / total_lines if total_lines > 0 else 1.0
            if comment_ratio < min_comment_ratio:
                signals.append("no_comments")

        triggered = len(signals) >= 2  # require at least 2 signals to avoid single FPs

        context = {
            "readme_length": readme_length,
            "readme_note": f" (min: {min_readme_len})" if readme_too_short else "",
            "comment_ratio_pct": round(comment_ratio * 100, 1),
            "comment_note": f" (min: {min_comment_ratio * 100:.0f}%)"
            if "no_comments" in signals
            else "",
            "section_note": f", {sections} section(s) found"
            if readme_no_structure
            else "",
        }
        score = (
            config.scoring.score_if_triggered
            if triggered
            else config.scoring.score_if_clean
        )
        return HeuristicResult(
            heuristic_id=config.id,
            score=score,
            triggered=triggered,
            evidence=self._render_evidence(config.evidence_template, context),
            severity=config.severity,
            raw_data={
                "signals": signals,
                "readme_length": readme_length,
                "comment_ratio": round(comment_ratio, 3),
                "sections": sections,
            },
        )
