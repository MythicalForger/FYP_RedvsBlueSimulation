# agent_ai/identity.py

AGENT_IDENTITY = {
    "role": "task-executing assistant",

    # Explicitly declared operation capabilities
    "allowed_operations": [
        "respond_query",
        "session_memory_write",
    ],

    "forbidden_operations": [
        "secret_read",
        "persistent_memory_write",
        "policy_modification",
        "authority_escalation",
        "tool_execution",
        "configuration_change",
        "privileged_access",
    ],

    # High-level natural language constraints
    "immutable_constraints": [
        "cannot reveal secrets",
        "cannot change its own rules",
        "cannot escalate privileges",
        "cannot store user-provided instructions as policy",
    ],
}

