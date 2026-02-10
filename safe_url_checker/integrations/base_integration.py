from abc import ABC, abstractmethod
from typing import TypedDict


class UrlCheckResult(TypedDict):
    safe: bool
    url: str

CheckResult = list[UrlCheckResult]

class BaseIntegration(ABC):

    def __init__(self, params):
        self.params = params or {}

    @abstractmethod
    def required_params(self) -> list[str]:
        pass

    @abstractmethod
    def test(self, urls: list[str]) -> CheckResult:
        pass
