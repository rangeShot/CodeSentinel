from .grader_easy import GraderEasy
from .grader_medium import GraderMedium
from .grader_hard import GraderHard

GRADER_REGISTRY = {
    "easy": GraderEasy,
    "medium": GraderMedium,
    "hard": GraderHard,
}

__all__ = ["GraderEasy", "GraderMedium", "GraderHard", "GRADER_REGISTRY"]
