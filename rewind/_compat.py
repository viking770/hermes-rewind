"""Stand-in base class used only when the plugin is imported outside Hermes
(for example by the unit tests). Inside Hermes the real
``agent.terminal_env_provider.TerminalEnvironmentProvider`` is used."""
from __future__ import annotations

import abc


class TerminalEnvironmentProvider(abc.ABC):
    is_remote = True
    is_container = True
    session_isolated_when_nonpersistent = False  # Hermes's default; RewindProvider opts in
    supports_streams = False

    @abc.abstractmethod
    def is_available(self) -> bool: ...

    @abc.abstractmethod
    def create_environment(self, *, cwd, timeout, task_id="default", image=None, container_config=None, **kwargs): ...
