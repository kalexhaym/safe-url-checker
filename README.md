# Installation
```
poetry add safe_url_checker
```

# Description
A library for checking links for security using several different integrations.

# How to use:
```
from safe_url_checker import SafeUrlChecker

checker = SafeUrlChecker()
checker.set_integrations([
    'GOOGLE_SAFE_BASE',
    'GOOGLE_SAFE_INTERSTITIAL',
    'GOOGLE_SAFE_TRANSPARENCY',
    'VIRUSTOTAL',
])
checker.set_integration_params('GOOGLE_SAFE_BASE', {
    'API_KEY': 'token'
})
checker.set_integration_params("VIRUSTOTAL", {
    'API_KEY': 'token'
})
check_result = checker.check(urls=[
    'https://google.com',
])
```
