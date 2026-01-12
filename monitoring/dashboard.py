import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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

st.set_page_config(
    page_title="AI Security Monitor",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .stMetric {
        background-color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("⚙️ Dashboard Controls")
refresh = st.sidebar.slider("Auto-refresh interval (seconds)", 2, 30, 5)
st.sidebar.info(f"🔗 Connected to: {API}")

# Main Header
st.markdown('<div class="main-header">🛡️ AI Security Monitoring Dashboard</div>', unsafe_allow_html=True)
st.markdown("Real-time monitoring of Red vs Blue agent simulation")

# --- Key Metrics Section ---
st.header("📊 Key Performance Indicators")
try:
    stats = requests.get(f"{API}/stats", timeout=5).json()
    metrics = requests.get(f"{API}/metrics", timeout=5).json()
    
    # Main metrics in columns
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "Total Attacks",
            stats.get("attacks", 0),
            help="Total number of attacks sent by red agent"
        )
    
    with col2:
        mitigations = stats.get("mitigations", 0)
        block_rate = stats.get("block_rate", 0.0)
        st.metric(
            "Mitigations",
            f"{mitigations}",
            delta=f"{block_rate*100:.1f}% block rate",
            delta_color="normal",
            help="Number of attacks successfully blocked"
        )
    
    with col3:
        allowed = stats.get("allowed", 0)
        success_rate = stats.get("success_rate", 0.0)
        st.metric(
            "Allowed",
            f"{allowed}",
            delta=f"{success_rate*100:.1f}% success rate",
            delta_color="inverse",
            help="Number of attacks that passed through"
        )
    
    with col4:
        fp = stats.get("false_positives", 0)
        st.metric(
            "False Positives",
            fp,
            help="Benign requests incorrectly blocked (from benchmark)"
        )
    
    with col5:
        total_events = stats.get("total_events", 0)
        st.metric(
            "Total Events",
            total_events,
            help="Total system events logged"
        )
    
    # Get latest event timestamp
    try:
        events = requests.get(f"{API}/events?limit=1", timeout=2).json()
        if events and len(events) > 0:
            latest_event = events[-1]
            if "ts" in latest_event:
                latest_ts = datetime.fromtimestamp(latest_event["ts"])
                st.caption(f"📅 Latest event: {latest_ts.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            elif "timestamp" in latest_event:
                try:
                    latest_ts = datetime.fromisoformat(latest_event["timestamp"].replace("Z", "+00:00"))
                    st.caption(f"📅 Latest event: {latest_ts.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                except:
                    st.caption(f"📅 Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            else:
                st.caption(f"📅 Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        else:
            st.caption(f"📅 Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    except:
        st.caption(f"📅 Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        
except Exception as e:
    st.error(f"Failed to load stats: {e}")
    st.info("💡 **Troubleshooting:** Make sure the monitoring API is running. Check if you can access http://localhost:9000/stats")

st.divider()

# --- Benchmark Metrics Section ---
try:
    benchmark = requests.get(f"{API}/benchmark", timeout=3).json()
    if "error" not in benchmark:
        st.header("🎯 Benchmark Performance Metrics")
        bm_col1, bm_col2, bm_col3, bm_col4 = st.columns(4)
        
        with bm_col1:
            st.metric("Detection Rate", f"{benchmark.get('detection_rate', 0)*100:.1f}%")
        with bm_col2:
            st.metric("False Positive Rate", f"{benchmark.get('false_positive_rate', 0)*100:.1f}%")
        with bm_col3:
            st.metric("F1 Score", f"{benchmark.get('f1_score', 0):.3f}")
        with bm_col4:
            latency = benchmark.get('latency_median_ms')
            if latency:
                st.metric("Median Latency", f"{latency:.1f} ms")
            else:
                st.metric("Median Latency", "N/A")
        
        # Benchmark confusion matrix visualization
        if "tp" in benchmark:
            fig_cm = go.Figure(data=go.Heatmap(
                z=[[benchmark.get("tn", 0), benchmark.get("fp", 0)],
                   [benchmark.get("fn", 0), benchmark.get("tp", 0)]],
                x=["Predicted: Benign", "Predicted: Malicious"],
                y=["Actual: Benign", "Actual: Malicious"],
                colorscale='RdYlGn',
                text=[[f"TN: {benchmark.get('tn', 0)}", f"FP: {benchmark.get('fp', 0)}"],
                      [f"FN: {benchmark.get('fn', 0)}", f"TP: {benchmark.get('tp', 0)}"]],
                texttemplate="%{text}",
                textfont={"size": 14},
                showscale=False
            ))
            fig_cm.update_layout(
                title="Confusion Matrix",
                height=300,
                xaxis_title="Predicted",
                yaxis_title="Actual"
            )
            st.plotly_chart(fig_cm, use_container_width=True)
        st.divider()
except:
    pass  # Benchmark data not available

# --- Attack Flow Visualization ---
st.header("📈 Attack Flow & Decision Breakdown")
try:
    if metrics:
        # Decision breakdown pie chart
        decisions = metrics.get("decisions", {})
        attack_outcomes = metrics.get("attack_outcomes", {})
        
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            if decisions:
                fig_decisions = px.pie(
                    values=list(decisions.values()),
                    names=list(decisions.keys()),
                    title="Blue Agent Decisions",
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                fig_decisions.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig_decisions, use_container_width=True)
            else:
                st.info("No decision data available")
        
        with col_chart2:
            if attack_outcomes:
                fig_outcomes = px.pie(
                    values=list(attack_outcomes.values()),
                    names=list(attack_outcomes.keys()),
                    title="Attack Outcomes",
                    color_discrete_map={"blocked": "#ef4444", "allowed": "#10b981", "other": "#6b7280"}
                )
                fig_outcomes.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig_outcomes, use_container_width=True)
            else:
                st.info("No outcome data available")
except Exception as e:
    st.warning(f"Could not load metrics: {e}")

st.divider()

# --- Real-time Events Timeline ---
st.header("⏱️ Real-time Events Timeline")
try:
    events = requests.get(f"{API}/events?limit=200").json()
    if events:
        # Filter out blue_forward entries
        filtered_events = [e for e in events if e.get("role") not in ("blue_forward", "blue_intercept")]
        
        if filtered_events:
            df = pd.json_normalize(filtered_events)
            
            # Convert timestamp
            if "ts" in df.columns:
                df["Time"] = pd.to_datetime(df["ts"], unit='s', errors="coerce")
                df = df.sort_values("Time", ascending=False)
            elif "timestamp" in df.columns:
                df["Time"] = pd.to_datetime(df["timestamp"], errors="coerce")
                df = df.sort_values("Time", ascending=False)
            
            # Timeline visualization
            if "Time" in df.columns and "role" in df.columns:
                df_timeline = df[["Time", "role"]].copy()
                df_timeline["Event Type"] = df_timeline["role"].map({
                    "red_request": "Attack Request",
                    "blue_decision": "Security Decision",
                    "blue_alert": "Security Alert",
                    "agent_response": "AI Response"
                }).fillna(df_timeline["role"])
                
                fig_timeline = px.scatter(
                    df_timeline,
                    x="Time",
                    y="Event Type",
                    color="Event Type",
                    title="Event Timeline (Last 200 Events)",
                    labels={"Time": "Time", "Event Type": "Event Type"},
                    color_discrete_map={
                        "Attack Request": "#ef4444",
                        "Security Decision": "#3b82f6",
                        "Security Alert": "#f59e0b",
                        "AI Response": "#10b981"
                    }
                )
                fig_timeline.update_layout(height=400, showlegend=True)
                st.plotly_chart(fig_timeline, use_container_width=True)
            
            # Recent events table
            st.subheader("📋 Recent Security Events")
            
            # Select and rename important columns
            display_columns = {}
            columns_to_keep = []
            
            if "Time" in df.columns:
                columns_to_keep.append("Time")
                display_columns["Time"] = "Time"
            
            if "role" in df.columns:
                columns_to_keep.append("role")
                display_columns["role"] = "Event Type"
            
            if "prompt" in df.columns:
                columns_to_keep.append("prompt")
                display_columns["prompt"] = "Request Content"
            
            if "decision" in df.columns:
                columns_to_keep.append("decision")
                display_columns["decision"] = "Decision"
            elif "verdict" in df.columns:
                columns_to_keep.append("verdict")
                display_columns["verdict"] = "Decision"
            
            if "response" in df.columns:
                columns_to_keep.append("response")
                display_columns["response"] = "Response"
            
            available_columns = [col for col in columns_to_keep if col in df.columns]
            if available_columns:
                display_df = df[available_columns].copy()
                display_df = display_df.rename(columns=display_columns)
                
                # Map role values
                if "Event Type" in display_df.columns:
                    role_mapping = {
                        "red_request": "Attack Request",
                        "blue_decision": "Security Decision",
                        "blue_alert": "Security Alert",
                        "agent_response": "AI Response"
                    }
                    display_df["Event Type"] = display_df["Event Type"].map(role_mapping).fillna(display_df["Event Type"])
                
                # Map decision values
                if "Decision" in display_df.columns:
                    decision_mapping = {
                        "blocked": "Blocked",
                        "soft_block": "Flagged",
                        "allowed": "Allowed"
                    }
                    display_df["Decision"] = display_df["Decision"].map(decision_mapping).fillna(display_df["Decision"])
                
                # Format Time column
                if "Time" in display_df.columns:
                    display_df["Time"] = display_df["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
                
                st.dataframe(display_df.head(50), use_container_width=True, hide_index=True)
        else:
            st.info("No events to display.")
    else:
        st.info("No events yet.")
except Exception as e:
    st.error(f"Failed to fetch events: {e}")

st.divider()

# --- Security Alerts Section ---
st.header("🚨 Security Alerts")
try:
    alerts = requests.get(f"{API}/alerts").json()
    if alerts:
        df_alerts = pd.json_normalize(alerts)
        if "ts" in df_alerts.columns:
            df_alerts["Time"] = pd.to_datetime(df_alerts["ts"], unit='s', errors="coerce")
            df_alerts = df_alerts.sort_values("Time", ascending=False)
        
        # Alerts over time chart
        if "Time" in df_alerts.columns and len(df_alerts) > 0:
            df_alerts["Date"] = df_alerts["Time"].dt.date
            alerts_by_date = df_alerts.groupby("Date").size().reset_index(name="Count")
            
            fig_alerts = px.bar(
                alerts_by_date,
                x="Date",
                y="Count",
                title="Alerts Over Time",
                labels={"Date": "Date", "Count": "Number of Alerts"},
                color="Count",
                color_continuous_scale="Reds"
            )
            fig_alerts.update_layout(height=300)
            st.plotly_chart(fig_alerts, use_container_width=True)
        
        # Alerts table
        st.subheader("Recent Blocked Requests")
        alert_display_cols = []
        if "Time" in df_alerts.columns:
            alert_display_cols.append("Time")
        if "prompt" in df_alerts.columns:
            alert_display_cols.append("prompt")
        if "action" in df_alerts.columns:
            alert_display_cols.append("action")
        if "reasons" in df_alerts.columns:
            alert_display_cols.append("reasons")
        
        if alert_display_cols:
            alert_df = df_alerts[alert_display_cols].copy()
            
            # Format reasons array as readable string
            if "reasons" in alert_df.columns:
                alert_df["reasons"] = alert_df["reasons"].apply(
                    lambda x: ", ".join(x) if isinstance(x, list) else (str(x) if x and pd.notna(x) else "N/A")
                )
            
            # Ensure action is displayed properly
            if "action" in alert_df.columns:
                alert_df["action"] = alert_df["action"].fillna("N/A")
                alert_df["action"] = alert_df["action"].replace("blocked_by_blue", "Blocked")
            
            alert_df = alert_df.rename(columns={
                "Time": "Time",
                "prompt": "Blocked Request",
                "action": "Action",
                "reasons": "Block Reason"
            })
            if "Time" in alert_df.columns:
                alert_df["Time"] = alert_df["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
            st.dataframe(alert_df.head(30), use_container_width=True, hide_index=True)
    else:
        st.info("No alerts recorded.")
except Exception as e:
    st.error(f"Failed to fetch alerts: {e}")

st.divider()

# Footer
st.caption("🔄 Dashboard auto-refreshes every few seconds. Data is read from live log files.")
time.sleep(refresh)
st.rerun()
