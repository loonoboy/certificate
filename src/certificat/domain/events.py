"""Progress events shared by future GUI and non-GUI clients."""

from dataclasses import dataclass
from enum import Enum


class ProgressStep(str, Enum):
    VALIDATING_INPUT = "validating_input"
    CHECKING_CONTAINER = "checking_container"
    EXTRACTING_CERTIFICATE = "extracting_certificate"
    EXTRACTING_PRIVATE_KEY = "extracting_private_key"
    VALIDATING_CERTIFICATE = "validating_certificate"
    VALIDATING_PRIVATE_KEY = "validating_private_key"
    MATCHING_KEY_PAIR = "matching_key_pair"
    SAVING_RESULTS = "saving_results"
    COMPLETED = "completed"


@dataclass(frozen=True)
class ProgressEvent:
    step: ProgressStep
    message: str

