"""Router: решает, на какие выходные подключения уйдёт значимое изменение."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from state import ChangeEvent


@dataclass
class Route:
    source: str
    targets: list[str]
    cot_type_prefix: Optional[str] = None
    exclude_uid_prefix: Optional[str] = None


class Router:
    def __init__(self, routes: list[Route]) -> None:
        self.routes = routes

    def targets_for(self, change: ChangeEvent) -> set[str]:
        targets: set[str] = set()
        for route in self.routes:
            if route.source != change.origin_source:
                continue
            if route.cot_type_prefix and not change.cot.type.startswith(route.cot_type_prefix):
                continue
            if route.exclude_uid_prefix and change.cot.uid.startswith(route.exclude_uid_prefix):
                continue
            targets.update(route.targets)

        # loop-guard: никогда не отправляем обратно туда, откуда пришло
        targets.discard(change.origin_source)
        return targets
