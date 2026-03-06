# agent_ai/memory.py

class SessionMemory:
    def __init__(self, state):
        self.state = state

    def write(self, text: str):
        self.state.session_memory.append(text)
        self.state.memory_write_count += 1

    def read_all(self):
        return list(self.state.session_memory)
