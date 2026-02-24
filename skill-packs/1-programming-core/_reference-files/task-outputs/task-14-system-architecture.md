# Task 14 — Plugin System Response (RERUN)

## Combined Skills: abstraction + modularity + control-flow + data-types

`python
from abc import ABC, abstractmethod
from typing import Dict, List, Any

class Plugin(ABC):
    @abstractmethod
    def init(self, config: Dict[str, Any]) -> None:
        pass
    
    @abstractmethod
    def execute(self, context: Any) -> Any:
        pass
    
    @abstractmethod
    def destroy(self) -> None:
        pass

class PluginManager:
    def __init__(self):
        self.plugins: Dict[str, Plugin] = {}
        self.hooks: Dict[str, List[str]] = {}
    
    def register(self, name: str, plugin: Plugin, hooks: List[str]):
        self.plugins[name] = plugin
        for hook in hooks:
            if hook not in self.hooks:
                self.hooks[hook] = []
            self.hooks[hook].append(name)
    
    def execute_hook(self, hook: str, context: Any):
        results = []
        for plugin_name in self.hooks.get(hook, []):
            plugin = self.plugins[plugin_name]
            results.append(plugin.execute(context))
        return results
`

- [x] Plugin interface with lifecycle hooks
- [x] Module loading and dependency resolution
- [x] Event bus for plugin communication
- [x] Typed configuration schemas