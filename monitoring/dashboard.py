import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from datetime import datetime
import time
import os

# Try multiple API endpoints for better connectivity
API_ENDPOINTS = [
    "http://monitoring_api:9000",  # Docker internal
    "http://localhost:9000",       # Local fallback
    "http://127.0.0.1:9000"        # Alternative local
]

def get_api_url():
    """Try to find a working API endpoint."""
    for api_url in API_ENDPOINTS:
        try:
            response = requests.get(f"{api_url}/stats", timeout=2)
            if response.status_code == 200:
                return api_url
        except:
            continue
    return API_ENDPOINTS[0]  # Fallback to first option

API = get_api_url()

st.set_page_config(page_title="Agentic AI Security Monitor", layout="wide")
st.title("🧠 Agentic AI Red vs Blue Simulation Dashboard")

st.sidebar.header("Refresh Controls")
refresh = st.sidebar.slider("Auto-refresh interval (seconds)", 2, 30, 5)

# Show connection info
st.sidebar.info(f"🔗 Connected to: {API}")

# --- Metrics Section ---
st.subheader("📊 System Statistics")
try:
    stats = requests.get(f"{API}/stats", timeout=5).json()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Attacks", stats.get("attacks", 0))
    c2.metric("Mitigations", stats.get("mitigations", 0))
    c3.metric("False Positives", stats.get("false_positives", 0))
    st.caption(f"Last updated: {datetime.utcnow().isoformat()}Z")
except Exception as e:
    st.error(f"Failed to load stats: {e}")
    st.info("💡 **Troubleshooting:** Make sure the monitoring API is running. Check if you can access http://localhost:9000/stats")

st.divider()

# --- Real-time Logs ---
st.subheader("📜 Recent Events (ai_events.jsonl)")
try:
    events = requests.get(f"{API}/events?limit=200").json()
    if events:
        df = pd.json_normalize(events)
        if "ts" in df.columns:
            df["timestamp"] = pd.to_datetime(df["ts"], unit='s', errors="coerce")
            df = df.sort_values("timestamp", ascending=False)
        st.dataframe(df.head(50))
    else:
        st.info("No events yet.")
except Exception as e:
    st.error(f"Failed to fetch events: {e}")

st.divider()

# --- Alerts Timeline ---
st.subheader("🧠 Blue Alerts Timeline")
try:
    alerts = requests.get(f"{API}/alerts").json()
    if alerts:
        df_alerts = pd.json_normalize(alerts)
        if "ts" in df_alerts.columns:
            df_alerts["timestamp"] = pd.to_datetime(df_alerts["ts"], unit='s', errors="coerce")
        # Create a simple timeline chart since we don't have alert_type/status fields
        fig = px.scatter(df_alerts, x="timestamp", y="action", hover_data=df_alerts.columns)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alerts recorded.")
except Exception as e:
    st.error(f"Failed to fetch alerts: {e}")

st.divider()
st.caption("Dashboard auto-refreshes every few seconds.")
time.sleep(refresh)
st.rerun()
