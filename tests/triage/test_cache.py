from agent.triage.cache import build_cache_key

def test_cache_key_is_deterministic():
    # If the kwargs are provided in the same way, hash should be exactly the same.
    hash1 = build_cache_key(
        incident_id="INC-1",
        incident_content_hash="123",
        model="llama3",
        provider="groq",
        prompt_version="1.0",
        schema_version="1.0"
    )
    
    hash2 = build_cache_key(
        incident_id="INC-1",
        incident_content_hash="123",
        model="llama3",
        provider="groq",
        prompt_version="1.0",
        schema_version="1.0"
    )
    
    assert hash1 == hash2
    assert isinstance(hash1, str)
    assert len(hash1) == 64 # SHA-256 hexdigest length
