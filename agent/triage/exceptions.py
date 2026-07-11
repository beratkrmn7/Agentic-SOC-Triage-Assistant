from agent.triage.enums import ReviewReason

class TriageProviderError(Exception):
    def __init__(self, message="Triage provider error", review_reason=ReviewReason.NONE):
        super().__init__(message)
        self.review_reason = review_reason

class ProviderConfigurationError(TriageProviderError):
    def __init__(self, message="Provider configuration missing"):
        super().__init__(message, ReviewReason.PROVIDER_CONFIGURATION_ERROR)

class ProviderUnavailableError(TriageProviderError):
    def __init__(self, message="Provider is unavailable"):
        super().__init__(message, ReviewReason.PROVIDER_UNAVAILABLE)

class ProviderTimeoutError(TriageProviderError):
    def __init__(self, message="Provider timed out"):
        super().__init__(message, ReviewReason.PROVIDER_TIMEOUT)

class ProviderRateLimitError(TriageProviderError):
    def __init__(self, message="Provider rate limit exceeded"):
        super().__init__(message, ReviewReason.PROVIDER_RATE_LIMITED)

class ProviderAuthenticationError(TriageProviderError):
    def __init__(self, message="Provider authentication failed"):
        super().__init__(message, ReviewReason.PROVIDER_AUTHENTICATION_FAILED)

class ProviderInvalidResponseError(TriageProviderError):
    def __init__(self, message="Provider returned invalid response"):
        super().__init__(message, ReviewReason.INVALID_LLM_OUTPUT)
