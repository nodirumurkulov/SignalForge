from app.core.extraction import extract_indicators
from app.core.models import IndicatorType


def test_extracts_defanged_urls_hashes_ips_and_emails() -> None:
    text = """
    hxxp://secure-login-update.example-attacker.net/session
    operator@example-attacker.net
    185.199.108.153
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """

    indicators = extract_indicators(text, "unit-test")
    values = {indicator.value for indicator in indicators}
    types = {indicator.value: indicator.type for indicator in indicators}

    assert "http://secure-login-update.example-attacker.net/session" in values
    assert "operator@example-attacker.net" in values
    assert "185.199.108.153" in values
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in values
    assert types["185.199.108.153"] == IndicatorType.IPV4
    assert (
        types["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        == IndicatorType.SHA256
    )


def test_deduplicates_indicators() -> None:
    indicators = extract_indicators("8.8.8.8 8.8.8.8 hxxp://a.example/path hxxp://a.example/path", "x")

    assert [indicator.value for indicator in indicators].count("8.8.8.8") == 1
    assert [indicator.value for indicator in indicators].count("http://a.example/path") == 1
