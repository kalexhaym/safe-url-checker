import pytest

from safe_url_checker import SafeUrlChecker, IntegrationNotFound


def test_set_integrations_not_found():
    checker = SafeUrlChecker()

    with pytest.raises(IntegrationNotFound):
        checker.set_integrations(['test'])

def test_set_integrations():
    checker = SafeUrlChecker()

    checker.set_integrations(['GOOGLE_SAFE_BASE'])
    assert checker.selected_integrations == ['GOOGLE_SAFE_BASE']