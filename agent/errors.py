class ConfigurationError(Exception):
    """Raised when there is an issue with application configuration or environment variables."""
    pass

class ParserError(Exception):
    """Raised when an unrecoverable error occurs during parsing."""
    pass

class UnsupportedSchemaError(Exception):
    """Raised when a log format cannot be parsed by any available parser."""
    pass

class EvidenceValidationError(Exception):
    """Raised when evidence validation strictly fails processing."""
    pass

class LLMProviderError(Exception):
    """Raised when the LLM provider is unreachable or returns an error."""
    pass
