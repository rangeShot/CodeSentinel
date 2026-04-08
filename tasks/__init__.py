from .task_easy import EasyTask
from .task_medium import MediumTask
from .task_hard import HardTask

TASK_REGISTRY = {
    "easy": EasyTask,
    "medium": MediumTask,
    "hard": HardTask,
}

__all__ = ["EasyTask", "MediumTask", "HardTask", "TASK_REGISTRY"]
