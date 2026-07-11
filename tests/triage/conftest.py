import pytest
from typing import List, Any

class FakeRunnable:
    def __init__(self, actions: List[Any]):
        self.actions = actions
        self.call_count = 0
        
    def invoke(self, messages: List[Any], **kwargs):
        if self.call_count >= len(self.actions):
            raise Exception("No more actions scripted")
            
        action = self.actions[self.call_count]
        self.call_count += 1
        
        if isinstance(action, Exception):
            raise action
            
        return action

class ScriptableFakeLLM:
    def __init__(self, actions: List[Any]):
        self.runnable = FakeRunnable(actions)
        
    def bind_tools(self, tools: List[Any], **kwargs):
        return self.runnable

@pytest.fixture
def fake_llm():
    def _create(actions: List[Any]):
        return ScriptableFakeLLM(actions)
    return _create
