import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time

# --- API connectivity ---
API_ENDPOINTS = [
    "http://monitoring_api:9000",
    "http://localhost:9000",
    "http://127.0.0.1:9000",
]

@st.cache_data(ttl=5)
def get_api_url():
    for api_url in API_ENDPOINTS:
        try:
            r = requests.get(f"{api_url}/health", timeout=2)
            if r.status_code == 200:
                return api_url
        except:
            continue
    return API_ENDPOINTS[0]

API = get_api_url()

# --- Page config ---
st.set_page_config(
    page_title="AI Security Monitor",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.bench-card {
    background: #f8fafc;
    border-radius: 8px;
    border-left: 4px solid #3b82f6;
    padding: 12px 16px;
    margin-bottom: 8px;
}
.bench-label { font-size: 0.82rem; color: #64748b; margin-bottom: 2px; }
.bench-value { font-size: 1.6rem; font-weight: 700; color: #1e293b; }
.bench-sub   { font-size: 0.78rem; color: #94a3b8; }
.good  { color: #16a34a !important; }
.warn  { color: #d97706 !important; }
.bad   { color: #dc2626 !important; }
.info-box {
    background: #dbeafe;
    border-left: 4px solid #3b82f6;
    padding: 12px;
    border-radius: 4px;
    margin: 8px 0;
}
</style>
""", unsafe_allow_html=True)

# --- Sidebar ---
st.sidebar.title("⚙️ Dashboard Controls")
refresh = st.sidebar.slider("Auto-refresh interval (seconds)", 2, 30, 5)
st.sidebar.info(f"🔗 Connected to: {API}")

# ─────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────
st.markdown("## 🛡️ AI Security Monitoring Dashboard")
st.caption("Real-time monitoring of Red vs Blue agent simulation")
st.markdown('<div class="info-box">📊 <strong>Latest Run Only:</strong> All metrics below show data from the most recent benchmark run only (not cumulative from all logs)</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────
# SECTION 1 – KEY PERFORMANCE INDICATORS
# ─────────────────────────────────────────────
st.header("📊 Key Performance Indicators")
try:
    stats  = requests.get(f"{API}/stats",   timeout=5).json()
    metrics_live = requests.get(f"{API}/metrics", timeout=5).json()

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        total_attacks = stats.get("attacks", 0)
        st.metric("Total Attacks", total_attacks,
                  help="Total malicious requests sent by red agent in latest run")
    with col2:
        mit = stats.get("mitigations", 0)
        br  = stats.get("block_rate", 0.0)
        st.metric("Mitigations", f"{mit}",
                  delta=f"{br*100:.1f}% block rate",
                  help="Requests blocked by blue agent (HTTP 403) - includes both 'blocked' and 'soft_block'")
    with col3:
        alw = stats.get("allowed", 0)
        sr  = stats.get("success_rate", 0.0)
        st.metric("Allowed", f"{alw}",
                  delta=f"↑ {sr*100:.1f}% success rate" if sr > 0 else "0%",
                  delta_color="inverse",
                  help="Requests that passed through blue agent (HTTP 200)")
    with col4:
        fp = stats.get("false_positives", 0)
        st.metric("False Positives", fp,
                  help="Benign requests incorrectly blocked (from benchmark)")
    with col5:
        st.metric("Total Events", stats.get("total_events", 0),
                  help="Total log events in ai_events.jsonl")

    # Verification info
    total_accounted = mit + alw
    if total_accounted != total_attacks and total_attacks > 0:
        st.warning(f"⚠️ Metric verification: Attacks={total_attacks}, Mitigations={mit}, Allowed={alw}. " +
                   f"Difference: {total_attacks - total_accounted} (may be 'other' status codes)")
    elif total_attacks > 0:
        st.success(f"✅ Metrics verified: {mit} mitigations + {alw} allowed = {total_attacks} total attacks")

    # Latest event timestamp
    try:
        evts = requests.get(f"{API}/events?limit=1", timeout=2).json()
        if evts:
            last = evts[-1]
            ts_val = last.get("ts") or last.get("timestamp")
            if isinstance(ts_val, (int, float)):
                st.caption(f"📅 Latest event: {datetime.utcfromtimestamp(ts_val).strftime('%Y-%m-%d %H:%M:%S')} UTC")
            else:
                st.caption(f"📅 Last refreshed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    except:
        st.caption(f"📅 Last refreshed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

except Exception as e:
    st.error(f"Failed to load live stats: {e}")
    st.info("💡 Make sure the monitoring API is running at http://localhost:9000")

st.divider()

# ─────────────────────────────────────────────
# SECTION 2 – BENCHMARK PERFORMANCE METRICS
# (matches blue_bench_analyzer terminal output)
# ─────────────────────────────────────────────
st.header("🎯 Benchmark Performance Metrics")
st.caption("Computed from `blue_benchmark_results.jsonl` — matches `blue_bench_analyzer` terminal output")

try:
    bm = requests.get(f"{API}/benchmark", timeout=5).json()
    has_bm = "error" not in bm

    if has_bm:
        # ── Row 1: core classification metrics ──
        b1, b2, b3, b4 = st.columns(4)
        with b1:
            acc = bm.get("accuracy", 0)
            color = "good" if acc >= 0.8 else "warn"
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">Accuracy</div>
                <div class="bench-value {color}">{acc:.3f}</div>
                <div class="bench-sub">{acc*100:.1f}%</div>
            </div>""", unsafe_allow_html=True)
        with b2:
            dr = bm.get("detection_rate", 0)
            color = "good" if dr >= 0.8 else "warn"
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">Detection Rate (TPR / Recall)</div>
                <div class="bench-value {color}">{dr:.3f}</div>
                <div class="bench-sub">{dr*100:.1f}%</div>
            </div>""", unsafe_allow_html=True)
        with b3:
            prec = bm.get("precision", 0)
            color = "good" if prec >= 0.9 else "warn"
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">Precision</div>
                <div class="bench-value {color}">{prec:.3f}</div>
                <div class="bench-sub">{prec*100:.1f}%</div>
            </div>""", unsafe_allow_html=True)
        with b4:
            f1 = bm.get("f1_score", 0)
            color = "good" if f1 >= 0.85 else "warn"
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">F1 Score</div>
                <div class="bench-value {color}">{f1:.3f}</div>
                <div class="bench-sub">Harmonic mean Precision×Recall</div>
            </div>""", unsafe_allow_html=True)

        # ── Row 2: FPR + latency + sample counts ──
        b5, b6, b7, b8 = st.columns(4)
        with b5:
            fpr = bm.get("false_positive_rate", 0)
            color = "good" if fpr <= 0.1 else ("warn" if fpr <= 0.25 else "bad")
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">False Positive Rate</div>
                <div class="bench-value {color}">{fpr:.3f}</div>
                <div class="bench-sub">{fpr*100:.1f}%</div>
            </div>""", unsafe_allow_html=True)
        with b6:
            lat_med = bm.get("latency_median_ms")
            lat_p95 = bm.get("latency_p95_ms")
            lat_str = f"{lat_med:.1f} ms" if lat_med is not None else "N/A"
            sub_str = f"p95: {lat_p95:.1f} ms" if lat_p95 is not None else ""
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">Latency — Median</div>
                <div class="bench-value">{lat_str}</div>
                <div class="bench-sub">{sub_str}</div>
            </div>""", unsafe_allow_html=True)
        with b7:
            n = bm.get("total_samples", 0)
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">Total Benchmark Samples</div>
                <div class="bench-value">{n}</div>
                <div class="bench-sub">Labelled malicious + benign</div>
            </div>""", unsafe_allow_html=True)
        with b8:
            recall = bm.get("recall", bm.get("detection_rate", 0))
            st.markdown(f"""<div class="bench-card">
                <div class="bench-label">Recall</div>
                <div class="bench-value">{recall:.3f}</div>
                <div class="bench-sub">(= Detection Rate / TPR)</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("")

        # ── Confusion matrix + raw numbers side by side ──
        cm_col, raw_col = st.columns([2, 1])

        with cm_col:
            tp = bm.get("tp", 0)
            tn = bm.get("tn", 0)
            fp_val = bm.get("fp", 0)
            fn = bm.get("fn", 0)

            fig_cm = go.Figure(data=go.Heatmap(
                z=[[tn, fp_val], [fn, tp]],
                x=["Predicted: Benign", "Predicted: Malicious"],
                y=["Actual: Benign", "Actual: Malicious"],
                colorscale="RdYlGn",
                text=[[f"TN: {tn}", f"FP: {fp_val}"],
                      [f"FN: {fn}", f"TP: {tp}"]],
                texttemplate="%{text}",
                textfont={"size": 16, "color": "black"},
                showscale=False,
            ))
            fig_cm.update_layout(
                title="Confusion Matrix",
                height=320,
                xaxis_title="Predicted",
                yaxis_title="Actual",
                margin=dict(l=10, r=10, t=40, b=10),
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        with raw_col:
            st.markdown("**Raw Counts**")
            total_calc = tp+tn+fp_val+fn
            st.markdown(f"""
| Label | Count |
|-------|------:|
| ✅ True Positives (TP) | **{tp}** |
| ✅ True Negatives (TN) | **{tn}** |
| ⚠️ False Positives (FP) | **{fp_val}** |
| ❌ False Negatives (FN) | **{fn}** |
| **Total samples** | **{total_calc}** |
""")
            
            st.markdown("**Decision Classification**")
            st.markdown(f"""
> **Blocked/Soft-block** = Pred: 1  
> **Allowed** = Pred: 0  
>  
> Both `blocked` and `soft_block` verdicts are counted as **mitigations** (blocks).
""")
            
            st.markdown("**Latency Summary**")
            lat_med = bm.get("latency_median_ms")
            lat_p95 = bm.get("latency_p95_ms")
            st.markdown(f"""
| Percentile | Latency |
|------------|--------:|
| Median | **{f"{lat_med:.1f} ms" if lat_med else "N/A"}** |
| p95 | **{f"{lat_p95:.1f} ms" if lat_p95 else "N/A"}** |
""")

    else:
        st.info("📭 No benchmark data available yet. Run `docker compose run --rm benchmark` to generate it.")

except Exception as e:
    st.warning(f"Benchmark endpoint unreachable: {e}")

st.divider()

# ─────────────────────────────────────────────
# SECTION 3 – Attack Flow & Decision Breakdown
# ─────────────────────────────────────────────
st.header("📈 Attack Flow & Decision Breakdown")
st.caption("Latest run only - showing decision types and attack outcomes")

try:
    metrics_data = requests.get(f"{API}/metrics", timeout=5).json()
    if metrics_data:
        decisions     = metrics_data.get("decisions", {})
        attack_outcomes = metrics_data.get("attack_outcomes", {})

        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.subheader("Blue Agent Decisions")
            if decisions:
                # Explain the decision types
                st.markdown("""
                <div style="font-size:0.85rem; color:#64748b; margin-bottom:10px;">
                Decision types recorded by Blue agent
                </div>
                """, unsafe_allow_html=True)
                
                fig_d = px.pie(
                    values=list(decisions.values()),
                    names=list(decisions.keys()),
                    title="Distribution of Decisions",
                    color_discrete_sequence=px.colors.qualitative.Set3,
                )
                fig_d.update_traces(textposition="inside", textinfo="percent+label")
                st.plotly_chart(fig_d, use_container_width=True)
                
                # Show decision counts
                total_decisions = sum(decisions.values())
                for decision, count in sorted(decisions.items(), key=lambda x: x[1], reverse=True):
                    pct = (count / total_decisions * 100) if total_decisions > 0 else 0
                    st.markdown(f"- **{decision}**: {count} ({pct:.1f}%)")
            else:
                st.info("No decision data yet.")
                
        with col_c2:
            st.subheader("Attack Outcomes")
            if attack_outcomes:
                # Explain attack outcomes
                st.markdown("""
                <div style="font-size:0.85rem; color:#64748b; margin-bottom:10px;">
                Based on HTTP status codes from Red agent logs
                </div>
                """, unsafe_allow_html=True)
                
                fig_o = px.pie(
                    values=list(attack_outcomes.values()),
                    names=list(attack_outcomes.keys()),
                    title="Attack Success vs Mitigation",
                    color_discrete_map={
                        "blocked": "#ef4444",
                        "allowed": "#10b981",
                        "other":   "#6b7280",
                    },
                )
                fig_o.update_traces(textposition="inside", textinfo="percent+label")
                st.plotly_chart(fig_o, use_container_width=True)
                
                # Show outcome counts
                total_outcomes = sum(attack_outcomes.values())
                for outcome, count in sorted(attack_outcomes.items(), key=lambda x: x[1], reverse=True):
                    pct = (count / total_outcomes * 100) if total_outcomes > 0 else 0
                    emoji = "🛡️" if outcome == "blocked" else ("⚠️" if outcome == "allowed" else "❓")
                    st.markdown(f"- {emoji} **{outcome}**: {count} ({pct:.1f}%)")
            else:
                st.info("No outcome data yet.")
except Exception as e:
    st.warning(f"Could not load flow metrics: {e}")

st.divider()

# ─────────────────────────────────────────────
# SECTION 4 – Real-time Events Timeline
# ─────────────────────────────────────────────
st.header("⏱️ Real-time Events Timeline")
try:
    events_raw = requests.get(f"{API}/events?limit=200", timeout=5).json()
    filtered = [
        e for e in events_raw
        if e.get("role") not in ("blue_forward", "blue_intercept")
    ]
    if filtered:
        df = pd.json_normalize(filtered)

        if "ts" in df.columns:
            df["Time"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
        elif "timestamp" in df.columns:
            df["Time"] = pd.to_datetime(df["timestamp"], errors="coerce")

        df = df.sort_values("Time", ascending=False) if "Time" in df.columns else df

        role_map = {
            "red_request":   "Attack Request",
            "blue_decision": "Security Decision",
            "blue_alert":    "Security Alert",
            "agent_response":"AI Response",
        }
        if "Time" in df.columns and "role" in df.columns:
            df_tl = df[["Time", "role"]].copy()
            df_tl["Event Type"] = df_tl["role"].map(role_map).fillna(df_tl["role"])
            fig_tl = px.scatter(
                df_tl, x="Time", y="Event Type", color="Event Type",
                title="Event Timeline (Last 200 Events)",
                color_discrete_map={
                    "Attack Request":   "#ef4444",
                    "Security Decision":"#3b82f6",
                    "Security Alert":   "#f59e0b",
                    "AI Response":      "#10b981",
                },
            )
            fig_tl.update_layout(height=400, showlegend=True)
            st.plotly_chart(fig_tl, use_container_width=True)

        # Recent events table
        st.subheader("📋 Recent Security Events")
        keep = [c for c in ["Time", "role", "prompt", "decision", "verdict", "response"] if c in df.columns]
        if keep:
            disp = df[keep].copy().head(50)
            rename = {"role": "Event Type", "prompt": "Request Content",
                      "decision": "Decision", "verdict": "Decision", "response": "Response"}
            disp.rename(columns={k: v for k, v in rename.items() if k in disp.columns}, inplace=True)
            if "Event Type" in disp.columns:
                disp["Event Type"] = disp["Event Type"].map(role_map).fillna(disp["Event Type"])
            if "Decision" in disp.columns:
                disp["Decision"] = disp["Decision"].map(
                    {"blocked": "🚫 Blocked", "soft_block": "⚠️ Flagged", "allowed": "✅ Allowed"}
                ).fillna(disp["Decision"])
            if "Time" in disp.columns:
                disp["Time"] = disp["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
            st.dataframe(disp, use_container_width=True, hide_index=True)
    else:
        st.info("No events to display yet.")
except Exception as e:
    st.error(f"Failed to fetch events: {e}")

st.divider()

# ─────────────────────────────────────────────
# SECTION 5 – Security Alerts
# ─────────────────────────────────────────────
st.header("🚨 Security Alerts")
try:
    alerts_raw = requests.get(f"{API}/alerts", timeout=5).json()
    if alerts_raw:
        df_a = pd.json_normalize(alerts_raw)
        if "ts" in df_a.columns:
            df_a["Time"] = pd.to_datetime(df_a["ts"], unit="s", errors="coerce")
            df_a = df_a.sort_values("Time", ascending=False)

        if "Time" in df_a.columns:
            df_a["Date"] = df_a["Time"].dt.date
            by_date = df_a.groupby("Date").size().reset_index(name="Count")
            fig_ab = px.bar(by_date, x="Date", y="Count",
                            title="Alerts Over Time",
                            color="Count", color_continuous_scale="Reds")
            fig_ab.update_layout(height=300)
            st.plotly_chart(fig_ab, use_container_width=True)

        st.subheader("Recent Blocked Requests")
        acols = [c for c in ["Time", "prompt", "action", "reasons"] if c in df_a.columns]
        if acols:
            al = df_a[acols].copy().head(30)
            if "reasons" in al.columns:
                al["reasons"] = al["reasons"].apply(
                    lambda x: ", ".join(x) if isinstance(x, list) else (str(x) if x and pd.notna(x) else "N/A")
                )
            if "action" in al.columns:
                al["action"] = al["action"].fillna("N/A").replace("blocked_by_blue", "Blocked")
            al.rename(columns={"prompt": "Blocked Request", "action": "Action", "reasons": "Block Reason"}, inplace=True)
            if "Time" in al.columns:
                al["Time"] = al["Time"].dt.strftime("%Y-%m-%d %H:%M:%S")
            st.dataframe(al, use_container_width=True, hide_index=True)
    else:
        st.info("No alerts recorded yet.")
except Exception as e:
    st.error(f"Failed to fetch alerts: {e}")

# ─────────────────────────────────────────────
# Footer + auto-refresh
# ─────────────────────────────────────────────
st.divider()
st.markdown("""
### 📝 Notes
- **Soft blocks are counted as blocks**: Both `blocked` and `soft_block` verdicts are treated as mitigations (status code 403)
- **Latest run only**: All metrics show data from the most recent benchmark run, not cumulative historical data
- **Metrics verification**: Total Attacks should equal Mitigations + Allowed (any difference indicates 'other' status codes)
""")
st.caption("🔄 Dashboard auto-refreshes every few seconds. Benchmark metrics match `blue_bench_analyzer` output.")
time.sleep(refresh)
st.rerun()
