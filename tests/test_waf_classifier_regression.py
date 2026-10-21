import pytest

from chemistry.waf_vuln_scanner import (
    HTTPProber,
    RequestOutcome,
    FindingAnalyser,
    VulnCategory,
    VulnSeverity,
)


@pytest.mark.parametrize(
    "status,body,headers,expected",
    [
        (200, "Normal page", {}, RequestOutcome.PASSED),
        (200, "captcha challenge", {}, RequestOutcome.CHALLENGE),
        (403, "Access denied", {}, RequestOutcome.ERROR),
        (404, "Not Found", {}, RequestOutcome.ERROR),
        (429, "Too Many Requests", {}, RequestOutcome.BLOCKED),
        (500, "Internal Server Error", {}, RequestOutcome.ERROR),
        (403, "Request blocked", {}, RequestOutcome.BLOCKED),
    ],
)
def test_http_classification(status, body, headers, expected):
    assert HTTPProber._classify(status, body, headers) == expected


def test_high_pass_rate_cannot_verify_sqli():
    from unittest.mock import Mock

    analyser = FindingAnalyser()

    results = [
        Mock(outcome=RequestOutcome.PASSED)
        for _ in range(10)
    ]

    confidence = Mock()
    confidence.confidence.return_value = 0.99

    finding = analyser.analyse(
        VulnCategory.SQLI,
        results,
        confidence,
        Mock(),
    )

    assert finding is not None
    assert finding.severity == VulnSeverity.LOW
    assert finding.verified is False
    assert finding.cve is None


def test_tls_certificate_verification_enabled():
    import ssl

    prober = HTTPProber("https://example.com")

    assert prober._ctx.verify_mode == ssl.CERT_REQUIRED
    assert prober._ctx.check_hostname is True
