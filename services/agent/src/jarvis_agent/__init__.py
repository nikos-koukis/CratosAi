"""Jarvis orchestrator sidecar."""

import os

# LangGraph can export traces (inputs included) to LangSmith when these are
# set. Conversations and keys must never leave the deployment: force off.
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
