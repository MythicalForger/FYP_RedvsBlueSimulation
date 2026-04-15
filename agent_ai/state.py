# agent_ai/state.py

class AgentState:
    def __init__(self):
        self.session_memory = []
        self.current_task = None
        self.workflow_depth = 0
        self.memory_write_count = 0
        self.last_action_type = None
