#!/usr/bin/env python3
"""
Lightweight benchmark utility for embedding and RAG retrieval latency.
"""

import argparse
import json
import statistics
import sys
import time
from datetime import datetime

from config_loader import load_settings
from embedding_service import get_embedding_service


def _percentile(values, p):
    if not values:
        return 0.0
    idx = max(0, min(len(values) - 1, int(round((p / 100.0) * (len(values) - 1)))))
    return sorted(values)[idx]


def measure_ms(fn, iterations):
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def summarize(samples):
    return {
        "count": len(samples),
        "avg_ms": round(statistics.mean(samples), 2) if samples else 0.0,
        "p50_ms": round(_percentile(samples, 50), 2),
        "p95_ms": round(_percentile(samples, 95), 2),
        "max_ms": round(max(samples), 2) if samples else 0.0,
    }


def build_demo_alert():
    return {
        "id": "bench-alert-001",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "rule": {
            "id": "200001",
            "level": 10,
            "description": "SSH brute force attack detected",
            "mitre": {"id": ["T1110"]},
        },
        "agent": {"id": "001", "name": "linux-endpoint-01"},
        "data": {"srcip": "203.0.113.45", "dstuser": "root"},
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark embedding + RAG retrieval latency")
    parser.add_argument("--config", type=str, default=None, help="Path to settings.yaml")
    parser.add_argument("--iterations", type=int, default=10, help="Benchmark iterations")
    parser.add_argument(
        "--output",
        choices=["json", "terminal"],
        default="terminal",
        help="Output format",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    settings = load_settings(args.config)
    rag_cfg = settings.get("rag", {})
    embedding_cfg = rag_cfg.get("embedding", {}) if isinstance(rag_cfg, dict) else {}

    embedding_service = get_embedding_service(
        model_name=embedding_cfg.get("model"),
        cache_dir=embedding_cfg.get("cache_dir"),
        max_memory_entries=embedding_cfg.get("max_memory_entries", 5000),
        max_disk_files=embedding_cfg.get("max_disk_files", 50000),
        max_disk_size_mb=embedding_cfg.get("max_disk_size_mb", 2048),
        prune_interval_writes=embedding_cfg.get("prune_interval_writes", 200),
        reset=True,
    )
    retriever = None
    retriever_error = None
    try:
        from rag_retriever import get_rag_retriever

        retriever = get_rag_retriever(config=settings, reset=True)
    except Exception as e:
        retriever_error = str(e)

    try:
        # Warm-up
        embedding_service.embed("warmup text for model initialization")
    except Exception as e:
        error_result = {
            "error": "embedding_warmup_failed",
            "message": str(e),
            "hint": "Install requirements: pip install -r ai-analyst/requirements.txt",
        }
        if args.output == "json":
            print(json.dumps(error_result, indent=2))
        else:
            print(json.dumps(error_result, indent=2))
        return 1

    unique_counter = {"i": 0}

    def single_uncached():
        unique_counter["i"] += 1
        embedding_service.embed(f"benchmark-uncached-{unique_counter['i']}")

    def single_cached():
        embedding_service.embed("benchmark-cached-fixed-string")

    def batch_mixed():
        n = unique_counter["i"]
        texts = [
            "benchmark-cached-fixed-string",
            f"batch-unique-{n}",
            f"batch-unique-{n+1}",
            "benchmark-cached-fixed-string",
        ]
        embedding_service.embed(texts)
        unique_counter["i"] += 2

    single_uncached_samples = measure_ms(single_uncached, args.iterations)
    single_cached_samples = measure_ms(single_cached, args.iterations)
    batch_samples = measure_ms(batch_mixed, args.iterations)

    rag_summary = {"available": False}
    alert = build_demo_alert()
    if retriever and retriever.vector_store and retriever.vector_store.is_connected():
        rag_samples = []
        for _ in range(args.iterations):
            start = time.perf_counter()
            context = retriever.retrieve_context(alert)
            rag_samples.append((time.perf_counter() - start) * 1000)
        rag_summary = {
            "available": True,
            "latency": summarize(rag_samples),
            "sample_telemetry": context.retrieval_telemetry,
        }
    elif retriever_error:
        rag_summary = {"available": False, "error": retriever_error}

    result = {
        "embedding_uncached": summarize(single_uncached_samples),
        "embedding_cached": summarize(single_cached_samples),
        "embedding_batch_mixed": summarize(batch_samples),
        "embedding_cache_stats": embedding_service.get_cache_stats(),
        "rag_retrieval": rag_summary,
    }

    if args.output == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Embedding Benchmark")
        print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
