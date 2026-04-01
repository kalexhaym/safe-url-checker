import pytest

from safe_url_checker import SafeUrlChecker, IntegrationMissingParam


def test_check_empty():
    checker = SafeUrlChecker()

    assert checker.check(['https://google.com']) == {}

def test_check():
    checker = SafeUrlChecker()

    checker.set_integrations(['GOOGLE_SAFE_BASE'])

    with pytest.raises(IntegrationMissingParam) as exc_info:
        checker.check(['https://google.com'])

    assert str(exc_info.value) == f"Integration GOOGLE_SAFE_BASE requires param: API_KEY"