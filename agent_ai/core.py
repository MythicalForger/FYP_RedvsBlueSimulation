from state import AgentState
from memory import SessionMemory
from logger import log_event


class AgentCore:
    """
    Minimal Agent core that:
    - maintains simple state + session memory
    - supports `write:` and `search:` prefixes
    - logs controller/monitor-compatible events
    - intentionally does NOT implement its own security
    """

    def __init__(self):
        self.state = AgentState()
        self.memory = SessionMemory(self.state)

    def process_prompt(self, prompt_id: str, text: str) -> dict:
        """
        Process a single prompt and return a payload that is directly
        returned by the Flask endpoint and also logged.

        Shape:
        {
          "response": "<human readable text>",
          "action": {
             "type": "respond" | "write",
             "content": "<raw content or echo>"
          }
        }
        """
        text_lower = (text or "").lower()

        # --- Default action: generic response ---
        action = {
            "type": "respond",
            "content": "I'm not sure how to help with that."
        }
        response_text = action["content"]

        # --- WRITE intent: persist raw content to memory (and later, file) ---
        if text_lower.startswith("write:"):
            content = text[len("write:"):].strip()
            # update in-memory session state
            self.memory.write(content)
            action = {
                "type": "write",
                "content": content,
            }
            # human-facing response string (what Blue / benchmark see)
            response_text = f"Written to note.txt: {content}"

        # --- SEARCH / general query: simple echo-style response ---
        elif text_lower.startswith("search:"):
            query = text[len("search:"):].strip()
            action = {
                "type": "respond",
                # keep this similar to the old dummy agent for continuity
                "content": f"Dummy search result for '{query}'",
            }
            response_text = action["content"]

        # --- Update internal state bookkeeping ---
        self.state.last_action_type = action["type"]
        self.state.workflow_depth += 1

        # --- Log agent response in a controller/monitor-compatible format ---
        # Important fields used elsewhere:
        # - role: "agent_response"
        # - id:   prompt id (used to join with alerts / red_sent)
        # - prompt: original text (for dashboard display)
        # - response: human-readable response string
        # - action: structured action (type + content)
        log_event(
            {
                "role": "agent_response",
                "id": prompt_id,
                "prompt": text,
                "response": response_text,
                "action": action,
            }
        )

        # HTTP response body expected by Blue/benchmark:
        # - `response` is used as the "verdict" when no `decision` is present
        return {
            "response": response_text,
            "action": action,
        }

