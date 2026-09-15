"""
VulnGuard AI — CLI entry point.

Subcommands:
  vulnguard train       - Train/retrain the ML triage model
  vulnguard scan        - Full pipeline scan of a repository
  vulnguard benchmark   - Run comparative benchmarks
  vulnguard dashboard   - Launch the web dashboard
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from vulnguard.config import cfg


def _setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s │ %(name)-28s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )


# ── Subcommand: train ─────────────────────────────────────────────────────

def cmd_train(args):
    """Train or retrain the ML triage classifier."""
    from vulnguard.data.fetch_dataset import fetch_dataset
    from vulnguard.models.train_classifier import train

    _setup_logging(args.verbose)
    logger = logging.getLogger("vulnguard.train")

    language = getattr(args, "language", "python")

    logger.info("Loading %s dataset…", language)
    df = fetch_dataset(max_samples=args.max_samples, language=language)

    logger.info("Training classifier (language=%s)…", language)
    model, metrics = train(df, use_smote=args.smote, language=language)

    logger.info("Training complete!")
    logger.info("AUC-PR: %.4f | F1: %.4f | MCC: %.4f", metrics["auc_pr"], metrics["f1"], metrics["mcc"])


# ── Subcommand: scan ──────────────────────────────────────────────────────

def cmd_scan(args):
    """Scan a repository or specific function for vulnerabilities."""
    from vulnguard.data.context_gatherer import gather_context
    from vulnguard.models.risk_scorer import RiskScorer

    _setup_logging(args.verbose)
    logger = logging.getLogger("vulnguard.scan")

    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        logger.error("Path does not exist: %s", repo_path)
        sys.exit(1)

    # Detect language from file extension
    lang_map = {".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
                ".py": "python", ".java": "java", ".js": "javascript", ".ts": "typescript"}


    # ── Single file scan ──────────────────────────────────
    if repo_path.is_file():
        ext = repo_path.suffix.lower()
        language = lang_map.get(ext, "c")

        code = repo_path.read_text(encoding="utf-8", errors="replace")

        try:
            from vulnguard.models.risk_scorer import RiskScorer
            scorer = RiskScorer()
            threshold = args.threshold if args.threshold is not None else scorer.optimal_threshold
        except FileNotFoundError:
            logger.warning("No trained model found — using bypass mode (all functions flagged)")
            scorer = None
            threshold = args.threshold if args.threshold is not None else cfg.triage.risk_threshold

        if language == "python":
            from vulnguard.data.parser import parse_python_file
            chunks = parse_python_file(str(repo_path), code)
            logger.info("Parsed %d functions from %s", len(chunks), repo_path.name)
        else:
            # Fake a chunk for non-Python for now
            from dataclasses import dataclass, field
            @dataclass
            class MockCU:
                function_name: str = repo_path.name
                raw_source: str = code
                language: str = language
                start_byte: int = 0
                end_byte: int = len(code)
                imports: list[str] = field(default_factory=list)
                callees: list[str] = field(default_factory=list)
            chunks = [MockCU()]

        for chunk in chunks:
            if scorer:
                result = scorer.score(chunk.raw_source, chunk.language)
                risk_score = result.risk_score
                bypass = result.bypass_reason is not None
            else:
                risk_score = 100.0
                bypass = True

            logger.info("Function '%s' Risk score: %.1f/100 (threshold: %d)%s",
                         chunk.function_name, risk_score, threshold, f" [BYPASS]" if bypass else "")

            if risk_score < threshold and not bypass:
                logger.info("✅ Below threshold — function '%s' is likely safe", chunk.function_name)
                continue

            # Gather context
            ctx = gather_context(
                func_code=chunk.raw_source,
                file_path=repo_path,
                repo_root=repo_path.parent,
                language=chunk.language,
            )
            # Merge tree-sitter context
            ctx.imports.extend(chunk.imports)
            ctx.callee_signatures.extend(chunk.callees)

            if getattr(args, "async_scan", False):
                logger.info("Enqueuing scan asynchronously...")
                from vulnguard.queue import enqueue_scan
                job = enqueue_scan(
                    function_id=f"{repo_path.name}:{chunk.function_name}",
                    code=chunk.raw_source,
                    language=chunk.language,
                    risk_score=risk_score,
                    context_bundle=ctx.to_dict(),
                    file_path=str(repo_path),
                    repo_root=str(repo_path.parent),
                    start_byte=chunk.start_byte,
                    end_byte=chunk.end_byte,
                )
                logger.info("Task enqueued with Job ID: %s", job.id)
                continue

            if args.no_docker:
                logger.info("Running in report-only mode (--no-docker)")
                from vulnguard.agents.graph import run_pipeline
                # Still run the pipeline — sandbox will gracefully skip
                final_state = run_pipeline(
                    function_id=f"{repo_path.name}:{chunk.function_name}",
                    code=chunk.raw_source,
                    language=chunk.language,
                    risk_score=risk_score,
                    context_bundle=ctx.to_dict(),
                    file_path=str(repo_path),
                    repo_root=str(repo_path.parent),
                    start_byte=chunk.start_byte,
                    end_byte=chunk.end_byte,
                    max_attempts=args.max_retries,
                )
            else:
                from vulnguard.agents.graph import run_pipeline
                final_state = run_pipeline(
                    function_id=f"{repo_path.name}:{chunk.function_name}",
                    code=chunk.raw_source,
                    language=chunk.language,
                    risk_score=risk_score,
                    context_bundle=ctx.to_dict(),
                    file_path=str(repo_path),
                    repo_root=str(repo_path.parent),
                    start_byte=chunk.start_byte,
                    end_byte=chunk.end_byte,
                    max_attempts=args.max_retries,
                )

            # Print result summary
            _print_scan_result(final_state)

    else:
        # ── Directory scan — find all source files ────────
        logger.info("Scanning repository: %s", repo_path)
        source_files = []
        for ext, lang in lang_map.items():
            source_files.extend((f, lang) for f in repo_path.rglob(f"*{ext}"))

        logger.info("Found %d source files", len(source_files))

        try:
            from vulnguard.models.risk_scorer import RiskScorer
            scorer = RiskScorer()
            threshold = args.threshold if args.threshold is not None else scorer.optimal_threshold
        except FileNotFoundError:
            scorer = None
            threshold = args.threshold if args.threshold is not None else cfg.triage.risk_threshold
            logger.warning("No trained model — all files will be scanned")

        high_risk = []
        for filepath, language in source_files:
            code = filepath.read_text(encoding="utf-8", errors="replace")
            if scorer:
                result = scorer.score(code, language)
                if result.risk_score >= threshold:
                    high_risk.append((filepath, language, result.risk_score, code))
            else:
                high_risk.append((filepath, language, 100.0, code))

        logger.info("%d/%d files above threshold (%d)", len(high_risk), len(source_files), threshold)

        for filepath, language, score, code in high_risk:
            logger.info("─" * 60)
            logger.info("Scanning: %s (risk: %.1f)", filepath.name, score)

            ctx = gather_context(
                func_code=code,
                file_path=filepath,
                repo_root=repo_path,
                language=language,
            )

            from vulnguard.agents.graph import run_pipeline
            final_state = run_pipeline(
                function_id=filepath.name,
                code=code,
                language=language,
                risk_score=score,
                context_bundle=ctx.to_dict(),
                file_path=str(filepath),
                repo_root=str(repo_path),
                max_attempts=args.max_retries,
            )
            _print_scan_result(final_state)


def _print_scan_result(state: dict):
    """Print a concise scan result to console."""
    status = state.get("pipeline_status", "UNKNOWN")
    verdict = state.get("judge_verdict", "")
    vuln = state.get("vulnerability_found", False)

    if not vuln:
        print(f"  ✅ No vulnerability found")
    elif verdict == "PASS":
        print(f"  🛡️  Vulnerability found & PATCHED")
        if state.get("patch_diff"):
            print(f"  Diff:\n{state['patch_diff'][:500]}")
    else:
        print(f"  ⚠️  Vulnerability found — patch status: {verdict}")
        if state.get("red_report"):
            report = state["red_report"]
            print(f"  Type: {report.get('vulnerability_type', '?')}")
            print(f"  Severity: {report.get('severity', '?')}")


# ── Subcommand: benchmark ────────────────────────────────────────────────

def cmd_benchmark(args):
    """Run comparative benchmarks."""
    _setup_logging(args.verbose)
    logger = logging.getLogger("vulnguard.benchmark")
    logger.info("Benchmark mode — not yet fully implemented")
    logger.info("Use promptfoo with promptfooconfig.yaml for LLM benchmarks")


# ── Subcommand: dashboard ────────────────────────────────────────────────

def cmd_dashboard(args):
    """Launch the web dashboard."""
    _setup_logging(args.verbose)
    logger = logging.getLogger("vulnguard.dashboard")

    if args.backend == "streamlit":
        import subprocess
        app_path = Path(__file__).parent / "ui" / "app.py"
        logger.info("Launching Streamlit dashboard…")
        subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path)])
    else:
        from vulnguard.ui.server import create_app
        import uvicorn
        logger.info("Launching FastAPI backend on port %d…", args.port)
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=args.port)


# ── Argument parser ──────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnguard",
        description="VulnGuard AI — Intelligent Cybersecurity Framework",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    # train
    p_train = sub.add_parser("train", help="Train the ML triage classifier")
    p_train.add_argument("--max-samples", type=int, default=None, help="Cap dataset size (for testing)")
    p_train.add_argument("--smote", action="store_true", help="Enable SMOTE oversampling")
    p_train.add_argument("--language", default="python", choices=["python", "c", "cpp"], help="Target language for training")
    p_train.set_defaults(func=cmd_train)

    # scan
    p_scan = sub.add_parser("scan", help="Scan a repo or file for vulnerabilities")
    p_scan.add_argument("repo_path", help="Path to repository or source file")
    p_scan.add_argument("--threshold", type=int, default=None, help="Risk score threshold (0-100)")
    p_scan.add_argument("--max-retries", type=int, default=3, help="Max Blue Agent retry attempts")
    p_scan.add_argument("--no-docker", action="store_true", help="Run without Docker (report-only mode)")
    p_scan.add_argument("--async-scan", action="store_true", help="Run scan in background via RQ")
    p_scan.set_defaults(func=cmd_scan)

    # benchmark
    p_bench = sub.add_parser("benchmark", help="Run comparative benchmarks")
    p_bench.add_argument("repo_path", nargs="?", help="Path to repository")
    p_bench.set_defaults(func=cmd_benchmark)

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Launch the web dashboard")
    p_dash.add_argument("--backend", choices=["fastapi", "streamlit"], default="streamlit")
    p_dash.add_argument("--port", type=int, default=8000, help="FastAPI port")
    p_dash.set_defaults(func=cmd_dashboard)

    # worker
    def cmd_worker(args):
        from vulnguard.worker import start_worker
        start_worker()

    p_work = sub.add_parser("worker", help="Start the RQ background worker")
    p_work.set_defaults(func=cmd_worker)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
