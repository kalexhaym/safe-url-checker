from safe_url_checker.integrations.base_integration import CheckResult
from safe_url_checker.integrations import GoogleSafeBase, GoogleSafeInterstitial, GoogleSafeTransparency, Virustotal


INTEGRATIONS = {
    'GOOGLE_SAFE_BASE': GoogleSafeBase,
    'GOOGLE_SAFE_INTERSTITIAL': GoogleSafeInterstitial,
    'GOOGLE_SAFE_TRANSPARENCY': GoogleSafeTransparency,
    'VIRUSTOTAL': Virustotal,
}

class IntegrationNotFound(Exception):
    def __init__(self, integration: str):
        super().__init__(f"Integration not found: {integration}")

class IntegrationMissingParam(Exception):
    def __init__(self, integration: str, param: str):
        super().__init__(f"Integration '{integration}' requires param: {param}")

class SafeUrlChecker:
    def __init__(self) -> None:
        self.selected_integrations = []
        self.params = {}

    def _get_integration(self, integration: str):
        if integration in INTEGRATIONS:
            return INTEGRATIONS[integration]
        raise IntegrationNotFound(integration)

    def get_integrations_list(self) -> list[str]:
        return list(INTEGRATIONS.keys())

    def set_integrations(self, integrations: list[str]) -> None:
        for integration in integrations:
            if integration not in INTEGRATIONS:
                raise IntegrationNotFound(integration)
        self.selected_integrations = integrations

    def set_integration_params(self, integration: str, params: dict[str, str]) -> None:
        self.params[integration] = params

    def check(self, urls: list[str]) -> dict[str, CheckResult]:
        result = {}

        for integration in self.selected_integrations:

            integration_class = self._get_integration(integration)
            integration_class = integration_class(self.params.get(integration, {}))

            required_params = integration_class.required_params()
            for param in required_params:
                if integration not in self.params or param not in self.params[integration]:
                    raise IntegrationMissingParam(integration, param)

            result[integration] = integration_class.test(list(dict.fromkeys(urls)))

        return result
