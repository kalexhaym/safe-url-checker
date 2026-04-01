from safe_url_checker import SafeUrlChecker


def test_set_integration_params_not_found():
    checker = SafeUrlChecker()

    integrations = checker.get_integrations_list()

    assert integrations == ['GOOGLE_SAFE_BASE', 'GOOGLE_SAFE_INTERSTITIAL', 'GOOGLE_SAFE_TRANSPARENCY', 'VIRUSTOTAL']