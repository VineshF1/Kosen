from __future__ import annotations
import json
import asyncio
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict

from kosen.schemas import (
    BenchmarkVulnerability,
    BenchmarkResult,
    BenchmarkSummary,
    VerifiedFinding,
    VerificationStatus,
    FindingSeverity,
    SourceLocation,
)
from kosen.graph.workflow import run_review_sync


@dataclass
class EvaluationConfig:
    """Configuration for benchmark evaluation."""
    dataset_dir: str = "benchmark/dataset"
    max_vulns: Optional[int] = None
    output_file: str = "benchmark/results.json"
    parallel: bool = False  # Set True for async parallel evaluation


def evaluate_vulnerability(
    vuln: BenchmarkVulnerability,
    config: EvaluationConfig
) -> BenchmarkResult:
    """
    Evaluate the agentic code reviewer against a single vulnerability.
    
    Runs the reviewer on file_before.py + patch.diff and compares
    flagged findings against ground-truth bug line ranges.
    """
    # Run the review workflow
    # Use the pre-patch file as source (since we're simulating a PR review)
    source_files = {vuln.file_before_path: vuln.file_before_content}
    
    try:
        state = run_review_sync(
            diff_text=vuln.patch_diff,
            source_files=source_files,
        )
        flagged_findings = state.verified_findings
    except Exception as e:
        print(f"Error running review for {vuln.osv_id}: {e}")
        flagged_findings = []
    
    # Match findings to ground truth
    true_positives = 0
    false_positives = 0
    matched_ground_truth: set[tuple[int, int]] = set()
    
    for finding in flagged_findings:
        if finding.verification_status != VerificationStatus.VERIFIED:
            # Only count verified findings
            false_positives += 1
            continue
        
        # Check if finding overlaps with any ground truth bug range
        found_match = False
        for gt_start, gt_end in vuln.bug_line_ranges:
            find_start = finding.candidate.location.start_line
            find_end = finding.candidate.location.end_line
            
            # Check overlap
            if not (find_end < gt_start or find_start > gt_end):
                found_match = True
                matched_ground_truth.add((gt_start, gt_end))
                break
        
        if found_match:
            true_positives += 1
        else:
            false_positives += 1
    
    # False negatives = ground truth bugs not caught
    false_negatives = len(vuln.bug_line_ranges) - len(matched_ground_truth)
    
    return BenchmarkResult(
        vulnerability=vuln,
        flagged_findings=flagged_findings,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )


def evaluate_dataset(config: EvaluationConfig) -> BenchmarkSummary:
    """Evaluate the reviewer against the full benchmark dataset."""
    from benchmark.fetch_dataset import load_benchmark_dataset
    
    vulnerabilities = load_benchmark_dataset(config.dataset_dir)
    
    if config.max_vulns:
        vulnerabilities = vulnerabilities[:config.max_vulns]
    
    print(f"Evaluating {len(vulnerabilities)} vulnerabilities...")
    
    results: list[BenchmarkResult] = []
    for i, vuln in enumerate(vulnerabilities):
        print(f"  [{i+1}/{len(vulnerabilities)}] {vuln.osv_id} ({vuln.file_before_path})")
        result = evaluate_vulnerability(vuln, config)
        results.append(result)
        
        # Progress
        tp, fp, fn = result.true_positives, result.false_positives, result.false_negatives
        print(f"    TP={tp}, FP={fp}, FN={fn}, P={result.precision:.2%}, R={result.recall:.2%}")
    
    # Compute aggregate metrics
    total_tp = sum(r.true_positives for r in results)
    total_fp = sum(r.false_positives for r in results)
    total_fn = sum(r.false_negatives for r in results)
    
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    
    # Per-category breakdown
    per_category = {}
    for category in ["security", "performance", "syntax", "coverage"]:
        cat_results = [
            r for r in results 
            if any(f.candidate.category.value == category for f in r.flagged_findings)
        ]
        if cat_results:
            cat_tp = sum(r.true_positives for r in cat_results)
            cat_fp = sum(r.false_positives for r in cat_results)
            cat_fn = sum(r.false_negatives for r in cat_results)
            per_category[category] = {
                "precision": cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0.0,
                "recall": cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0.0,
                "true_positives": cat_tp,
                "false_positives": cat_fp,
                "false_negatives": cat_fn,
                "count": len(cat_results),
            }
    
    summary = BenchmarkSummary(
        total_vulnerabilities=len(vulnerabilities),
        total_true_positives=total_tp,
        total_false_positives=total_fp,
        total_false_negatives=total_fn,
        overall_precision=overall_precision,
        overall_recall=overall_recall,
        per_category=per_category,
    )
    
    # Save results
    output_path = Path(config.output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(asdict(summary), indent=2, default=str),
        encoding="utf-8"
    )
    
    # Also save detailed results
    detail_path = output_path.with_stem(output_path.stem + "_detail")
    detail_path.write_text(
        json.dumps([asdict(r) for r in results], indent=2, default=str),
        encoding="utf-8"
    )
    
    print(f"\n=== Benchmark Summary ===")
    print(f"Total Vulnerabilities: {summary.total_vulnerabilities}")
    print(f"True Positives: {summary.total_true_positives}")
    print(f"False Positives: {summary.total_false_positives}")
    print(f"False Negatives: {summary.total_false_negatives}")
    print(f"Overall Precision: {summary.overall_precision:.2%}")
    print(f"Overall Recall: {summary.overall_recall:.2%}")
    print(f"\nPer-Category:")
    for cat, metrics in summary.per_category.items():
        print(f"  {cat}: P={metrics['precision']:.2%}, R={metrics['recall']:.2%} (TP={metrics['true_positives']}, FP={metrics['false_positives']}, FN={metrics['false_negatives']})")
    
    print(f"\nResults saved to {config.output_file}")
    
    return summary


async def evaluate_dataset_async(config: EvaluationConfig) -> BenchmarkSummary:
    """Async parallel evaluation (optional)."""
    from benchmark.fetch_dataset import load_benchmark_dataset
    
    vulnerabilities = load_benchmark_dataset(config.dataset_dir)
    
    if config.max_vulns:
        vulnerabilities = vulnerabilities[:config.max_vulns]
    
    print(f"Evaluating {len(vulnerabilities)} vulnerabilities (async)...")
    
    semaphore = asyncio.Semaphore(5)  # Limit concurrency
    
    async def eval_one(vuln: BenchmarkVulnerability) -> BenchmarkResult:
        async with semaphore:
            # Run sync function in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, evaluate_vulnerability, vuln, config)
    
    results = await asyncio.gather(*[eval_one(v) for v in vulnerabilities])
    
    # Same aggregation as sync version
    total_tp = sum(r.true_positives for r in results)
    total_fp = sum(r.false_positives for r in results)
    total_fn = sum(r.false_negatives for r in results)
    
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    
    per_category = {}
    for category in ["security", "performance", "syntax", "coverage"]:
        cat_results = [
            r for r in results 
            if any(f.candidate.category.value == category for f in r.flagged_findings)
        ]
        if cat_results:
            cat_tp = sum(r.true_positives for r in cat_results)
            cat_fp = sum(r.false_positives for r in cat_results)
            cat_fn = sum(r.false_negatives for r in cat_results)
            per_category[category] = {
                "precision": cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0.0,
                "recall": cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0.0,
                "true_positives": cat_tp,
                "false_positives": cat_fp,
                "false_negatives": cat_fn,
                "count": len(cat_results),
            }
    
    summary = BenchmarkSummary(
        total_vulnerabilities=len(vulnerabilities),
        total_true_positives=total_tp,
        total_false_positives=total_fp,
        total_false_negatives=total_fn,
        overall_precision=overall_precision,
        overall_recall=overall_recall,
        per_category=per_category,
    )
    
    output_path = Path(config.output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(asdict(summary), indent=2, default=str),
        encoding="utf-8"
    )
    
    return summary


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate Kosen Code Reviewer on OSV benchmark")
    parser.add_argument("--dataset-dir", default="benchmark/dataset", help="Dataset directory")
    parser.add_argument("--max-vulns", type=int, help="Max vulnerabilities to evaluate")
    parser.add_argument("--output", default="benchmark/results.json", help="Output file")
    parser.add_argument("--async", dest="use_async", action="store_true", help="Run async parallel evaluation")
    
    args = parser.parse_args()
    
    config = EvaluationConfig(
        dataset_dir=args.dataset_dir,
        max_vulns=args.max_vulns,
        output_file=args.output,
        parallel=args.use_async,
    )
    
    if args.use_async:
        asyncio.run(evaluate_dataset_async(config))
    else:
        evaluate_dataset(config)


if __name__ == "__main__":
    main()