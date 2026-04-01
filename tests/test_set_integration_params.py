import pytest

from safe_url_checker import SafeUrlChecker, IntegrationNotFound


def test_set_integration_params_not_found():
    checker = SafeUrlChecker()

    with pytest.raises(IntegrationNotFound):
        checker.set_integration_params('test', {
            'API_KEY': 'token'
        })

def test_set_integration_params():
    checker = SafeUrlChecker()

    checker.set_integration_params('GOOGLE_SAFE_BASE', {
        'API_KEY': 'token'
    })

    assert checker.params == {'GOOGLE_SAFE_BASE': {
        'API_KEY': 'token'
    }}