#!/usr/bin/env python3
"""
Setup OpenSearch Vector Indices - Initialize k-NN indices and load initial data.

This script:
1. Creates the required OpenSearch indices with k-NN mappings
2. Indexes existing detection rules as playbooks
3. Optionally indexes historical alerts from Wazuh
4. Loads threat intelligence indicators

Usage:
    python setup_opensearch_vectors.py [--index-alerts] [--index-playbooks] [--index-threat-intel]

Environment Variables:
    OPENSEARCH_HOST: OpenSearch hostname (default: localhost)
    OPENSEARCH_PORT: OpenSearch port (default: 9200)
    OPENSEARCH_USER: Username (default: admin)
    OPENSEARCH_PASSWORD: Password (required)
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.vector_store import VectorStore
from src.embedding_service import EmbeddingService
from src.wazuh_client import WazuhClient

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def setup_indices(vector_store: VectorStore) -> bool:
    """Create all required OpenSearch indices."""
    logger.info("Creating OpenSearch indices with k-NN mappings...")

    success = vector_store.create_indices()

    if success:
        logger.info("✓ All indices created successfully")
    else:
        logger.error("✗ Failed to create some indices")

    return success


def index_playbooks(
    vector_store: VectorStore, embedding_service: EmbeddingService
) -> int:
    """
    Index incident response playbooks from markdown files.

    Args:
        vector_store: Vector store instance
        embedding_service: Embedding service instance

    Returns:
        Number of playbooks indexed
    """
    logger.info("Indexing incident response playbooks...")

    # Find playbook files
    playbooks_dir = (
        Path(__file__).parent.parent.parent / "incident-response" / "playbooks"
    )

    if not playbooks_dir.exists():
        logger.warning(f"Playbooks directory not found: {playbooks_dir}")
        return 0

    playbook_files = list(playbooks_dir.glob("*.md"))
    logger.info(f"Found {len(playbook_files)} playbook files")

    indexed_count = 0

    # Define playbook metadata based on filenames
    playbook_metadata = {
        "ssh-brute-force.md": {
            "id": "IR-PB-001",
            "title": "SSH Brute Force Response",
            "severity": "high",
            "mitre": ["T1110"],
            "description": "Procedures for responding to SSH brute force attacks",
        },
        "credential-dumping.md": {
            "id": "IR-PB-002",
            "title": "Credential Dumping Response",
            "severity": "critical",
            "mitre": ["T1003"],
            "description": "Procedures for responding to credential dumping attempts",
        },
        "powershell-abuse.md": {
            "id": "IR-PB-003",
            "title": "PowerShell Abuse Response",
            "severity": "high",
            "mitre": ["T1059.001"],
            "description": "Procedures for responding to malicious PowerShell activity",
        },
        "privilege-escalation.md": {
            "id": "IR-PB-004",
            "title": "Privilege Escalation Response",
            "severity": "high",
            "mitre": ["T1548"],
            "description": "Procedures for responding to privilege escalation attempts",
        },
        "persistence.md": {
            "id": "IR-PB-005",
            "title": "Persistence Mechanism Response",
            "severity": "high",
            "mitre": ["T1543"],
            "description": "Procedures for responding to persistence mechanisms",
        },
        "macos-compromise.md": {
            "id": "IR-PB-006",
            "title": "macOS Compromise Response",
            "severity": "high",
            "mitre": ["T1543.001", "T1543.004", "T1555.001"],
            "description": "Procedures for responding to macOS endpoint compromises",
        },
    }

    for playbook_file in playbook_files:
        filename = playbook_file.name
        metadata = playbook_metadata.get(filename, {})

        if not metadata:
            logger.warning(f"No metadata for {filename}, skipping")
            continue

        try:
            # Read playbook content
            content = playbook_file.read_text()

            # Create playbook document
            playbook_doc = {
                "title": metadata["title"],
                "description": metadata["description"],
                "severity": metadata["severity"],
                "mitre_techniques": metadata["mitre"],
                "file_path": str(playbook_file),
                "content": {"full_text": content[:5000]},  # Limit content size
            }

            # Generate embedding
            embedding = embedding_service.embed_playbook(playbook_doc)

            # Index playbook
            success = vector_store.index_playbook(
                playbook_id=metadata["id"],
                title=metadata["title"],
                description=metadata["description"],
                embedding=embedding,
                severity=metadata["severity"],
                mitre_techniques=metadata["mitre"],
                file_path=str(playbook_file),
                content=playbook_doc["content"],
            )

            if success:
                indexed_count += 1
                logger.info(f"  ✓ Indexed {metadata['id']}: {metadata['title']}")
            else:
                logger.error(f"  ✗ Failed to index {filename}")

        except Exception as e:
            logger.error(f"  ✗ Error indexing {filename}: {e}")

    logger.info(f"Indexed {indexed_count}/{len(playbook_files)} playbooks")
    return indexed_count


def index_threat_intel(
    vector_store: VectorStore, embedding_service: EmbeddingService
) -> int:
    """
    Index sample threat intelligence indicators.

    In production, this would load from threat intel feeds (AbuseIPDB, VirusTotal, etc.)

    Args:
        vector_store: Vector store instance
        embedding_service: Embedding service instance

    Returns:
        Number of indicators indexed
    """
    logger.info("Indexing threat intelligence indicators...")

    # Sample threat intel data
    threat_indicators = [
        {
            "value": "203.0.113.45",
            "type": "ip",
            "threat_type": "brute_force",
            "confidence": 0.95,
            "source": "sample",
            "description": "Known SSH brute force attacker",
        },
        {
            "value": "198.51.100.22",
            "type": "ip",
            "threat_type": "scanning",
            "confidence": 0.85,
            "source": "sample",
            "description": "Port scanning activity detected",
        },
        {
            "value": "192.0.2.100",
            "type": "ip",
            "threat_type": "malware_c2",
            "confidence": 0.90,
            "source": "sample",
            "description": "Known malware command and control server",
        },
        {
            "value": "malware-sample.exe",
            "type": "hash",
            "threat_type": "malware",
            "confidence": 0.98,
            "source": "sample",
            "description": "Known malware sample hash",
        },
    ]

    indexed_count = 0

    for indicator in threat_indicators:
        try:
            # Generate embedding
            embedding = embedding_service.embed_threat_intel(indicator)

            # Index indicator
            success = vector_store.index_threat_intel(
                ioc_value=indicator["value"],
                ioc_type=indicator["type"],
                embedding=embedding,
                threat_type=indicator["threat_type"],
                confidence=indicator["confidence"],
                source=indicator["source"],
                metadata={"description": indicator["description"]},
            )

            if success:
                indexed_count += 1
                logger.info(f"  ✓ Indexed {indicator['type']}: {indicator['value']}")
            else:
                logger.error(f"  ✗ Failed to index {indicator['value']}")

        except Exception as e:
            logger.error(f"  ✗ Error indexing {indicator['value']}: {e}")

    logger.info(f"Indexed {indexed_count}/{len(threat_indicators)} threat indicators")
    return indexed_count


def index_historical_alerts(
    vector_store: VectorStore,
    embedding_service: EmbeddingService,
    wazuh_client: WazuhClient,
    days: int = 7,
    batch_size: int = 100,
) -> int:
    """
    Index historical alerts from Wazuh.

    Args:
        vector_store: Vector store instance
        embedding_service: Embedding service instance
        wazuh_client: Wazuh API client
        days: Number of days to look back
        batch_size: Number of alerts to process in each batch

    Returns:
        Number of alerts indexed
    """
    logger.info(f"Indexing historical alerts from last {days} days...")

    if not wazuh_client:
        logger.warning("Wazuh client not available, skipping historical alerts")
        return 0

    # This would fetch real alerts from Wazuh API
    # For now, create some sample alerts for demonstration

    sample_alerts = [
        {
            "id": "historical-001",
            "rule": {
                "id": "100001",
                "description": "SSH brute force attack detected",
                "level": 10,
                "mitre": {"id": ["T1110"]},
            },
            "agent": {"id": "001", "name": "linux-endpoint-01"},
            "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            "timestamp": datetime.now().isoformat(),
        },
        {
            "id": "historical-002",
            "rule": {
                "id": "100021",
                "description": "Sudo abuse - shell escalation",
                "level": 10,
                "mitre": {"id": ["T1548.003"]},
            },
            "agent": {"id": "001", "name": "linux-endpoint-01"},
            "data": {"dstuser": "developer", "command": "sudo bash"},
            "timestamp": datetime.now().isoformat(),
        },
    ]

    indexed_count = 0

    for alert in sample_alerts:
        try:
            embedding = embedding_service.embed_alert(alert)
            success = vector_store.index_alert(alert, embedding)

            if success:
                indexed_count += 1
                logger.info(f"  ✓ Indexed alert {alert['id']}")
        except Exception as e:
            logger.error(f"  ✗ Error indexing alert {alert['id']}: {e}")

    logger.info(f"Indexed {indexed_count} historical alerts")
    return indexed_count


def main():
    parser = argparse.ArgumentParser(
        description="Setup OpenSearch vector indices for RAG"
    )
    parser.add_argument(
        "--index-playbooks",
        action="store_true",
        help="Index incident response playbooks",
    )
    parser.add_argument(
        "--index-threat-intel",
        action="store_true",
        help="Index threat intelligence indicators",
    )
    parser.add_argument(
        "--index-alerts", action="store_true", help="Index historical alerts from Wazuh"
    )
    parser.add_argument("--all", action="store_true", help="Index all data types")
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days to look back for historical alerts",
    )

    args = parser.parse_args()

    # If --all is specified, enable all indexing options
    if args.all:
        args.index_playbooks = True
        args.index_threat_intel = True
        args.index_alerts = True

    print("=" * 70)
    print("OpenSearch Vector Index Setup for SOC RAG")
    print("=" * 70)
    print()

    # Initialize services
    logger.info("Initializing services...")

    try:
        embedding_service = EmbeddingService()
        logger.info(
            f"✓ Embedding service initialized (dimension: {embedding_service.dimension})"
        )
    except Exception as e:
        logger.error(f"✗ Failed to initialize embedding service: {e}")
        return 1

    try:
        vector_store = VectorStore(embedding_dimension=embedding_service.dimension)

        if not vector_store.is_connected():
            logger.error("✗ Failed to connect to OpenSearch")
            logger.error(
                "  Make sure OpenSearch is running and credentials are correct"
            )
            logger.error(
                "  Set OPENSEARCH_HOST and OPENSEARCH_PASSWORD environment variables"
            )
            return 1

        logger.info("✓ Connected to OpenSearch")
    except Exception as e:
        logger.error(f"✗ Failed to connect to OpenSearch: {e}")
        return 1

    # Setup indices
    print()
    if not setup_indices(vector_store):
        return 1

    # Index data based on arguments
    results = {"playbooks": 0, "threat_intel": 0, "alerts": 0}

    if args.index_playbooks:
        print()
        results["playbooks"] = index_playbooks(vector_store, embedding_service)

    if args.index_threat_intel:
        print()
        results["threat_intel"] = index_threat_intel(vector_store, embedding_service)

    if args.index_alerts:
        print()
        wazuh_client = WazuhClient()
        results["alerts"] = index_historical_alerts(
            vector_store, embedding_service, wazuh_client, days=args.days
        )

    # Show final statistics
    print()
    print("=" * 70)
    print("Setup Complete!")
    print("=" * 70)
    print()

    stats = vector_store.get_stats()
    print("Index Statistics:")
    for index_name, info in stats.items():
        if "error" in info:
            print(f"  {index_name}: Error - {info['error']}")
        else:
            print(f"  {index_name}: {info.get('document_count', 0)} documents")

    print()
    print("Data Indexed:")
    print(f"  Playbooks: {results['playbooks']}")
    print(f"  Threat Intel: {results['threat_intel']}")
    print(f"  Historical Alerts: {results['alerts']}")

    print()
    print("Next Steps:")
    print("  1. Run alert analysis with RAG enabled:")
    print("     python src/analyze_alert.py --alert-id <id>")
    print()
    print("  2. Test similarity search:")
    print("     python src/rag_retriever.py")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
