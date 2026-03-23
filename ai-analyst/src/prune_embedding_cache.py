#!/usr/bin/env python3
"""
Prune embedding disk cache files by file count, total size, and age.
"""

import argparse
import json
import sys

from config_loader import load_settings
from embedding_service import get_embedding_service


def parse_args():
    parser = argparse.ArgumentParser(description="Prune embedding disk cache")
    parser.add_argument("--config", type=str, default=None, help="Path to settings.yaml")
    parser.add_argument("--max-files", type=int, default=None, help="Maximum cache files")
    parser.add_argument("--max-size-mb", type=int, default=None, help="Maximum cache size in MB")
    parser.add_argument("--max-age-days", type=int, default=None, help="Maximum cache file age in days")
    parser.add_argument("--dry-run", action="store_true", help="Compute deletions without removing files")
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

    service = get_embedding_service(
        model_name=embedding_cfg.get("model"),
        cache_dir=embedding_cfg.get("cache_dir"),
        max_memory_entries=embedding_cfg.get("max_memory_entries", 5000),
        max_disk_files=embedding_cfg.get("max_disk_files", 50000),
        max_disk_size_mb=embedding_cfg.get("max_disk_size_mb", 2048),
        prune_interval_writes=embedding_cfg.get("prune_interval_writes", 200),
        reset=True,
    )

    before = service.get_cache_stats()
    result = service.prune_disk_cache(
        max_files=args.max_files,
        max_size_mb=args.max_size_mb,
        max_age_days=args.max_age_days,
        dry_run=args.dry_run,
    )
    after = service.get_cache_stats()

    payload = {
        "result": result,
        "before": before,
        "after": after,
        "dry_run": args.dry_run,
    }

    if args.output == "json":
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(json.dumps(payload, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
