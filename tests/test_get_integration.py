import pytest

from safe_url_checker import SafeUrlChecker, IntegrationNotFound
from safe_url_checker.integrations import GoogleSafeBase, GoogleSafeInterstitial, GoogleSafeTransparency, Virustotal


def test_get_integration_not_found():
    checker = SafeUrlChecker()

    with pytest.raises(IntegrationNotFound):
        checker._get_integration('test')

def test_get_integration():
    checker = SafeUrlChecker()

    integration = checker._get_integration('GOOGLE_SAFE_BASE')
    assert isinstance(integration({}), GoogleSafeBase)

    integration = checker._get_integration('GOOGLE_SAFE_INTERSTITIAL')
    assert isinstance(integration({}), GoogleSafeInterstitial)

    integration = checker._get_integration('GOOGLE_SAFE_TRANSPARENCY')
    assert isinstance(integration({}), GoogleSafeTransparency)

    integration = checker._get_integration('VIRUSTOTAL')
    assert isinstance(integration({}), Virustotal)