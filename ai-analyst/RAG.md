# RAG (Retrieval-Augmented Generation) Implementation

## Overview

This implementation adds **RAG (Retrieval-Augmented Generation)** capabilities to the AI Alert Analyst, enabling the LLM to:

1. **Retrieve similar past incidents** for pattern recognition
2. **Match threat intelligence indicators** using semantic similarity
3. **Find relevant incident response playbooks** automatically
4. **Ground AI responses** in historical context and proven procedures

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ALERT ANALYSIS FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Wazuh Alert                                                     │
│       ↓                                                          │
│  ┌──────────────────────┐                                        │
│  │ 1. Generate Embedding │                                       │
│  │   (sentence-transformers)                                     │
│  └──────────┬───────────┘                                        │
│             ↓                                                    │
│  ┌──────────────────────┐                                        │
│  │ 2. RAG Retrieval      │                                       │
│  │   • Similar alerts    │←────┐                                 │
│  │   • Threat intel      │←──┐ │                                 │
│  │   • Playbooks         │←┐ │ │                                 │
│  └──────────┬───────────┘ │ │ │                                 │
│             ↓             │ │ │                                 │
│  ┌──────────────────────┐ │ │ │                                 │
│  │ 3. Context Assembly   │ │ │ │                                 │
│  │   (RAGContext)        │ │ │ │                                 │
│  └──────────┬───────────┘ │ │ │                                 │
│             ↓             │ │ │                                 │
│  ┌──────────────────────┐ │ │ │                                 │
│  │ 4. LLM Prompt         │ │ │ │                                 │
│  │   (alert + context)   │ │ │ │                                 │
│  └──────────┬───────────┘ │ │ │                                 │
│             ↓             │ │ │                                 │
│  ┌──────────────────────┐ │ │ │                                 │
│  │ 5. AI Analysis        │ │ │ │                                 │
│  │   (GPT-4/Claude)      │ │ │ │                                 │
│  └──────────┬───────────┘ │ │ │                                 │
│             ↓             │ │ │                                 │
│  ┌──────────────────────┐ │ │ │                                 │
│  │ 6. Index for Future   │─┘ │ │                                 │
│  │   (store in OpenSearch)  │ │                                 │
│  └──────────────────────┘─────┘                                 │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              OpenSearch k-NN Vector Store                 │   │
│  │  • soc-alerts-v1        - Historical alerts               │   │
│  │  • soc-threat-intel-v1  - IOCs and indicators            │   │
│  │  • soc-playbooks-v1     - IR procedures                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Embedding Service (`embedding_service.py`)

Generates vector embeddings using **sentence-transformers**:

- **Model**: `all-MiniLM-L6-v2` (384 dimensions, fast)
- **Alternative**: `all-mpnet-base-v2` (768 dimensions, higher quality)
- **Caching**: Automatic disk and memory caching for performance
- **Specialized methods**: For alerts, threat intel, and playbooks

```python
from embedding_service import get_embedding_service

service = get_embedding_service()
embedding = service.embed_alert(alert)
```

### 2. Vector Store (`vector_store.py`)

Manages OpenSearch k-NN indices:

| Index | Purpose | Key Fields |
|-------|---------|------------|
| `soc-alerts-v1` | Historical alerts | rule_id, agent_name, src_ip, embedding |
| `soc-threat-intel-v1` | IOCs | ioc_value, ioc_type, threat_type, embedding |
| `soc-playbooks-v1` | IR playbooks | title, mitre_techniques, severity, embedding |

**Features:**
- k-NN similarity search with HNSW algorithm
- Hybrid search (text + vector)
- Metadata filtering (time ranges, agents, etc.)

### 3. RAG Retriever (`rag_retriever.py`)

Orchestrates context retrieval:

```python
from rag_retriever import get_rag_retriever

retriever = get_rag_retriever()
context = retriever.retrieve_context(alert)

# Use in prompts
prompt_context = context.to_prompt_context()
```

**Retrieved Data:**
- Similar past incidents (last 7 days by default)
- Threat intelligence matches
- Relevant playbooks by MITRE technique
- Temporal context

### 4. AI Client Integration (`ai_client.py`)

Automatically uses RAG when analyzing alerts:

```python
from ai_client import AIClient

client = AIClient(use_rag=True)
analysis = client.analyze_alert(alert)

# RAG metadata included in response
print(analysis["rag_context"])
```

### 5. Alert Enricher (`alert_enricher.py`)

Automatically indexes alerts for future retrieval:

```python
from alert_enricher import AlertEnricher

enricher = AlertEnricher(enable_rag_indexing=True)
context = enricher.enrich(alert, index_for_rag=True)
```

## Setup

### Prerequisites

1. **OpenSearch** (included with Wazuh 4.x+)
2. **Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Environment Variables

```bash
# OpenSearch connection
export OPENSEARCH_HOST=localhost
export OPENSEARCH_PORT=9200
export OPENSEARCH_USER=admin
export OPENSEARCH_PASSWORD=your-password

# LLM API keys (for AI analysis)
export OPENAI_API_KEY=your-key
# OR
export ANTHROPIC_API_KEY=your-key
```

### Initialize Vector Indices

```bash
cd ai-analyst/src

# Index all data types
python setup_opensearch_vectors.py --all

# Or selectively
python setup_opensearch_vectors.py --index-playbooks
python setup_opensearch_vectors.py --index-threat-intel
python setup_opensearch_vectors.py --index-alerts --days 30
```

## Usage

### Basic RAG-Enhanced Analysis

```python
from ai_client import AIClient
from wazuh_client import WazuhClient

# Initialize clients
wazuh = WazuhClient()
ai = AIClient(use_rag=True)

# Get an alert
alert = wazuh.get_alert_by_id("100001")

# Analyze with RAG context
analysis = ai.analyze_alert(alert)

print(f"Title: {analysis['title']}")
print(f"Summary: {analysis['summary']}")

# Check RAG metadata
if 'rag_context' in analysis:
    rag = analysis['rag_context']
    print(f"Similar alerts retrieved: {rag['similar_alerts_count']}")
    print(f"Playbooks retrieved: {rag['playbooks_count']}")
```

### Manual RAG Retrieval

```python
from rag_retriever import get_rag_retriever

retriever = get_rag_retriever()

# Retrieve context manually
context = retriever.retrieve_context(alert)

# Access specific data
print(f"Found {len(context.similar_alerts)} similar alerts")
print(f"Found {len(context.threat_intel)} threat intel matches")
print(f"Found {len(context.relevant_playbooks)} relevant playbooks")

# Format for custom prompts
prompt_context = context.to_prompt_context(
    max_alerts=3,
    max_intel=2,
    max_playbooks=2
)
```

### Similarity Search

```python
from vector_store import get_vector_store
from embedding_service import get_embedding_service

vector_store = get_vector_store()
embedding_service = get_embedding_service()

# Create a query
query_text = "SSH brute force attack from unknown IP"
query_embedding = embedding_service.embed(query_text)

# Search for similar alerts
results = vector_store.search_similar_alerts(
    embedding=query_embedding,
    k=5,
    min_score=0.7,
    time_range="7d"
)

for result in results:
    print(f"{result['similarity_score']:.2%}: {result['rule_description']}")
```

## Configuration

Edit `config/settings.yaml`:

```yaml
rag:
  enabled: true
  
  embedding:
    model: "all-MiniLM-L6-v2"  # or "all-mpnet-base-v2"
    cache_dir: "~/.cache/ai-analyst/embeddings"
  
  opensearch:
    host: "localhost"
    port: 9200
    username: "admin"
    use_ssl: true
    verify_certs: false
  
  retrieval:
    similarity_threshold: 0.7  # Min similarity score (0-1)
    max_similar_alerts: 5
    max_threat_intel: 3
    max_playbooks: 2
    time_range: "7d"  # Lookback period
    hybrid_search: true
    text_weight: 0.3
    vector_weight: 0.7
  
  indexing:
    auto_index: true
    min_level: 5  # Minimum severity to index
```

## Benefits

### 1. Threat Intelligence Enrichment

**Without RAG:**
```
Alert: SSH brute force detected
AI: "This appears to be a brute force attack..."
```

**With RAG:**
```
Alert: SSH brute force detected

Retrieved Context:
• Similar alerts: 3 past incidents from IP 203.0.113.45
• Threat Intel: IP flagged in AbuseIPDB (95% confidence)
• Playbook: IR-PB-001 SSH Brute Force Response

AI: "This matches a known attacker (IP 203.0.113.45) with 95% confidence 
     based on 127 previous reports. Follow IR-PB-001 playbook and 
     immediately block this IP..."
```

### 2. Similarity-Based Alert Correlation

Finds semantically similar attacks even when:
- Rule IDs differ
- IP addresses change
- Attack variants evolve

```python
# These alerts will have high similarity despite different text:
"SSH brute force attack from 203.0.113.45"
"Multiple failed login attempts from 198.51.100.23"
"Authentication failures - possible credential stuffing"
```

### 3. Playbook Auto-Recommendation

Automatically suggests relevant playbooks based on:
- MITRE ATT&CK technique matching
- Semantic similarity to playbook descriptions
- Historical resolution patterns

## Performance

| Metric | Value |
|--------|-------|
| Embedding generation | ~50-100 alerts/second |
| Vector search latency | <100ms for k=10 |
| Memory usage | ~500MB (embedding model) |
| Index size | ~1KB per alert |

## Testing

```bash
# Test embedding service
python src/embedding_service.py

# Test vector store connection
python src/vector_store.py

# Test RAG retriever
python src/rag_retriever.py

# Run full setup
python src/setup_opensearch_vectors.py --all
```

## Troubleshooting

### Issue: OpenSearch connection fails

**Solution:**
```bash
# Check if OpenSearch is running
curl -k -u admin:admin https://localhost:9200

# Set correct environment variables
export OPENSEARCH_HOST=localhost
export OPENSEARCH_PASSWORD=your-password
```

### Issue: Embedding model download fails

**Solution:**
```bash
# Download manually or use cache
export SENTENCE_TRANSFORMERS_HOME=~/.cache/ai-analyst/embeddings
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
```

### Issue: Low similarity scores

**Solution:**
- Adjust `similarity_threshold` in settings.yaml
- Use larger embedding model (all-mpnet-base-v2)
- Ensure alerts have rich descriptions

## Future Enhancements

- [ ] Multi-modal embeddings (logs + alerts + pcaps)
- [ ] Temporal pattern detection
- [ ] Cross-customer threat intelligence
- [ ] Automated playbook recommendations based on resolution outcomes
- [ ] Real-time streaming ingestion

## References

- [OpenSearch k-NN Documentation](https://opensearch.org/docs/latest/search-plugins/knn/)
- [Sentence Transformers](https://www.sbert.net/)
- [RAG Pattern](https://www.promptingguide.ai/techniques/rag)
- [HNSW Algorithm](https://arxiv.org/abs/1603.09320)
