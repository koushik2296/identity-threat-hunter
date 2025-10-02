Use apply_honey_enrichment(doc) after normal enrichers and before indexing:
from app.middlewares.honey_guard import apply_honey_enrichment

def process_and_index(doc: dict):
    # ... existing enrichers (geoip/asn/etc.)
    doc = apply_honey_enrichment(doc)
    # ... index into Elastic
    return doc
