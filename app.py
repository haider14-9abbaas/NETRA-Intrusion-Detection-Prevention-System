# app.py
from __future__ import annotations

import time
from datetime import datetime
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

from services.auth import require_login, logout_button, is_admin, get_csrf_token, require_csrf
from services.anomaly_ml import add_anomaly_scores
from services.firewall import block_ip, unblock_ip, list_ids_rules
from services.ai_explainer import explain_alert
from utils.security import is_valid_ip, sanitize_text
from utils.safe_eval import safe_eval_bool


# ----------------------------
# Page config
# ----------------------------
st.set_page_config(
    page_title="NETRA IDS/IPS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------
# CSS
# ----------------------------
st.markdown(
    """
    <style>
      html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] { overflow-x: hidden !important; }
      .block-container { padding-top: 1.0rem; padding-bottom: 2rem; max-width: 100% !important; }
      [data-testid="stSidebar"] { min-width: 320px !important; max-width: 320px !important; }
      .metric-card { padding: 12px 14px !important; border: 1px solid rgba(255,255,255,0.10);
        border-radius: 12px; background: rgba(255,255,255,0.03); overflow: hidden !important; }
      .subtle { color: rgba(255,255,255,0.60); font-size: 0.85rem; }
      .header-row { display: flex; flex-direction: column; gap: 10px; width: 100%; }
      .header-left { width: 100%; min-width: 0; }
      .header-date { align-self: flex-end; max-width: 520px; width: auto !important; }
      .last-update { font-size: 1.05rem; font-weight: 800; line-height: 1.2; white-space: normal !important;
        overflow-wrap: anywhere !important; word-break: break-word !important; }
      .stDataFrame, .stTable { width: 100% !important; }
      @media (max-width: 900px) { .header-date { align-self: stretch; max-width: 100% !important; width: 100% !important; } }
    </style>
    """,
    unsafe_allow_html=True,
)

# ----------------------------
# Rules
# ----------------------------
DEFAULT_RULES = [
    {"name": "Brute Force Login", "type": "HIDS", "condition": "failed_logins > 5", "severity": "High",
     "desc": "Too many failed logins from same IP/user"},
    {"name": "Port Scan", "type": "NIDS", "condition": "ports_scanned >= 10", "severity": "High",
     "desc": "Single IP scanning many ports quickly"},
    {"name": "CPU Spike", "type": "HIDS", "condition": "cpu_percent >= 90", "severity": "Medium",
     "desc": "Sudden CPU spike can indicate malware / crypto mining"},
    {"name": "Traffic Spike", "type": "NIDS", "condition": "traffic_mbps >= 200", "severity": "Medium",
     "desc": "Unusual traffic spike (possible DDoS)"},
    {"name": "Suspicious File Change", "type": "HIDS", "condition": "file_integrity_changed == True", "severity": "High",
     "desc": "Integrity change detected in critical path"},
]


def eval_rule(rule, row) -> bool:
    """
    Secure evaluation using AST allowlist (NO raw eval).
    """
    ctx = {
        "failed_logins": row.get("failed_logins", 0),
        "ports_scanned": row.get("ports_scanned", 0),
        "cpu_percent": row.get("cpu_percent", 0),
        "traffic_mbps": row.get("traffic_mbps", 0),
        "file_integrity_changed": bool(row.get("file_integrity_changed", False)),
        "True": True,
        "False": False,
    }
    try:
        return safe_eval_bool(str(rule.get("condition", "")), ctx)
    except Exception:
        return False


def severity_style(val: str) -> str:
    v = (val or "").strip().lower()
    if v == "high":
        return "background-color: rgba(255, 0, 0, 0.20); color: #ffd6d6; font-weight: 700;"
    if v == "medium":
        return "background-color: rgba(255, 170, 0, 0.20); color: #ffe7b8; font-weight: 700;"
    if v == "low":
        return "background-color: rgba(0, 170, 255, 0.20); color: #cfefff; font-weight: 700;"
    return ""


# ----------------------------
# Sidebar
# ----------------------------
st.sidebar.title("Controls")
auth = require_login()
logout_button()

# CSRF token (for report + safety)
csrf_token = get_csrf_token()

# Live run-state
if "live_running" not in st.session_state:
    st.session_state.live_running = True

st.sidebar.divider()
mode = st.sidebar.selectbox("Mode", ["Simulation (Demo)", "Upload Logs (CSV)"])

refresh = st.sidebar.slider("Auto-refresh (seconds)", 0, 10, 1)
st.sidebar.caption("Note: Streamlit reruns on widget interaction (normal). Auto-refresh here is timer-based only.")

# Start/Stop buttons
st.sidebar.divider()
st.sidebar.subheader("▶ Live Feed Control")

c_run1, c_run2 = st.sidebar.columns(2)
with c_run1:
    if st.button("✅ Start", use_container_width=True):
        st.session_state.live_running = True
with c_run2:
    if st.button("⏸ Stop", use_container_width=True):
        st.session_state.live_running = False

st.sidebar.caption(f"Live Feed: **{'RUNNING' if st.session_state.live_running else 'STOPPED'}**")

# CSV streaming controls
st.sidebar.divider()
st.sidebar.subheader("CSV Streaming")
stream_csv = st.sidebar.checkbox("Stream CSV (Live Feed)", value=True)
rows_per_tick = st.sidebar.slider("Rows per refresh", 1, 50, 10)
window_size = st.sidebar.slider("Visible window (rows)", 20, 500, 120)
loop_csv = st.sidebar.checkbox("Loop at end", value=True)

# ML controls
st.sidebar.divider()
st.sidebar.subheader("🤖 ML Anomaly Detection")
enable_ml = st.sidebar.checkbox("Enable Isolation Forest", value=True)
contamination = st.sidebar.slider("Contamination", 0.01, 0.30, 0.08)

# Rules editor
st.sidebar.divider()
st.sidebar.subheader("Rules (Editable)")
rules_df = pd.DataFrame(DEFAULT_RULES)
edited_rules = st.sidebar.data_editor(
    rules_df,
    num_rows="dynamic",
    use_container_width=True,
    hide_index=True
)

# thresholds
st.sidebar.divider()
st.sidebar.subheader("Firewall Actions")
thr_failed = st.sidebar.number_input("Failed logins threshold", min_value=1, value=5)
thr_ports  = st.sidebar.number_input("Ports scanned threshold", min_value=1, value=10)
thr_cpu    = st.sidebar.number_input("CPU % threshold", min_value=1, value=90)
thr_traf   = st.sidebar.number_input("Traffic Mbps threshold", min_value=1, value=200)

for i, r in edited_rules.iterrows():
    if r.get("name") == "Brute Force Login":
        edited_rules.at[i, "condition"] = f"failed_logins > {thr_failed}"
    if r.get("name") == "Port Scan":
        edited_rules.at[i, "condition"] = f"ports_scanned >= {thr_ports}"
    if r.get("name") == "CPU Spike":
        edited_rules.at[i, "condition"] = f"cpu_percent >= {thr_cpu}"
    if r.get("name") == "Traffic Spike":
        edited_rules.at[i, "condition"] = f"traffic_mbps >= {thr_traf}"


# ----------------------------
# Header
# ----------------------------
header_box = st.empty()
clock_box = st.empty()

def render_header():
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header_box.markdown(
        f"""
        <div class="header-row">
          <div class="header-left">
            <h1 align="center" style="margin-bottom: 0.25rem;">🛡️ NETRA IDS/IPS</h1>
            <div class="subtle">Rule-based detection + ML anomaly + response actions + AI explanation</div>
          </div>
          <div class="header-date">
            <div class="metric-card">
              <div class="subtle">Last Update</div>
              <div class="last-update">{now_str}</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    clock_box.caption(f"🕒 Live Clock: **{datetime.now().strftime('%H:%M:%S')}**")

render_header()
st.divider()


# ----------------------------
# Data source helpers
# ----------------------------
def demo_data(n=25):
    import random
    rows = []
    for _ in range(n):
        rows.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "src_ip": f"192.168.1.{random.randint(2, 254)}",
            "user": random.choice(["student", "admin", "guest", "labuser"]),
            "failed_logins": random.choice([0, 0, 1, 2, 6, 10]),
            "ports_scanned": random.choice([0, 3, 5, 12, 25]),
            "cpu_percent": random.choice([10, 15, 30, 55, 92, 97]),
            "traffic_mbps": random.choice([5, 10, 25, 60, 210, 450]),
            "file_integrity_changed": random.choice([False, False, False, True]),
        })
    return pd.DataFrame(rows)


def normalize_csv_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    cols = {c.lower().strip(): c for c in df.columns}
    mapping = {}

    for k in ["src_ip", "source_ip", "ip", "srcip", "sourceip"]:
        if k in cols:
            mapping[cols[k]] = "src_ip"
            break
    for k in ["cpu_percent", "cpu_percentage", "cpu", "cpu%"]:
        if k in cols:
            mapping[cols[k]] = "cpu_percent"
            break
    for k in ["traffic_mbps", "traffic", "mbps", "trafficmbps", "net_mbps"]:
        if k in cols:
            mapping[cols[k]] = "traffic_mbps"
            break
    for k in ["file_integrity_changed", "integrity_changed", "file_change", "filechanged"]:
        if k in cols:
            mapping[cols[k]] = "file_integrity_changed"
            break
    for k in ["ports_scanned", "port_scans", "ports", "unique_ports"]:
        if k in cols:
            mapping[cols[k]] = "ports_scanned"
            break
    for k in ["failed_logins", "failed_login", "fail_logins", "login_failures"]:
        if k in cols:
            mapping[cols[k]] = "failed_logins"
            break
    for k in ["time", "timestamp", "datetime", "date_time"]:
        if k in cols:
            mapping[cols[k]] = "time"
            break

    if mapping:
        df = df.rename(columns=mapping)

    required_defaults = {
        "time": "N/A",
        "src_ip": "N/A",
        "user": "unknown",
        "failed_logins": 0,
        "ports_scanned": 0,
        "cpu_percent": 0,
        "traffic_mbps": 0,
        "file_integrity_changed": False,
    }
    for col, default in required_defaults.items():
        if col not in df.columns:
            df[col] = default

    df["file_integrity_changed"] = (
        df["file_integrity_changed"].astype(str).str.lower().isin(["true", "1", "yes", "y"])
    )
    for col in ["failed_logins", "ports_scanned", "cpu_percent", "traffic_mbps"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # sanitize string columns to avoid weird chars
    df["time"] = df["time"].astype(str).map(lambda x: sanitize_text(x, 60))
    df["src_ip"] = df["src_ip"].astype(str).map(lambda x: sanitize_text(x, 60))
    df["user"] = df["user"].astype(str).map(lambda x: sanitize_text(x, 60))

    return df[["time","src_ip","user","failed_logins","ports_scanned","cpu_percent","traffic_mbps","file_integrity_changed"]]


# ----------------------------
# CSV Streaming state
# ----------------------------
if "csv_df" not in st.session_state:
    st.session_state.csv_df = None
if "csv_pos" not in st.session_state:
    st.session_state.csv_pos = 0
if "csv_sig" not in st.session_state:
    st.session_state.csv_sig = None


# ----------------------------
# Load data
# ----------------------------
if mode == "Upload Logs (CSV)":
    up = st.file_uploader("Upload CSV logs", type=["csv"])
    st.caption("Expected columns: time, src_ip, user, failed_logins, ports_scanned, cpu_percent, traffic_mbps, file_integrity_changed")

    if up is None:
        st.info("👆 Upload a CSV file to start.")
        st.stop()

    sig = f"{up.name}-{up.size}"
    if st.session_state.csv_sig != sig:
        raw = pd.read_csv(up)
        st.session_state.csv_df = normalize_csv_columns(raw)
        st.session_state.csv_sig = sig

        total_now = len(st.session_state.csv_df)
        st.session_state.csv_pos = min(rows_per_tick, total_now) if total_now > 0 else 0

    base_df = st.session_state.csv_df
    total = len(base_df)

    if total > 0 and st.session_state.csv_pos == 0:
        st.session_state.csv_pos = min(rows_per_tick, total)

    colA, colB = st.columns([1, 1])
    with colA:
        if st.button("▶ Next Chunk", use_container_width=True):
            st.session_state.csv_pos += rows_per_tick
    with colB:
        if st.button("⟲ Reset Stream", use_container_width=True):
            st.session_state.csv_pos = min(rows_per_tick, total) if total > 0 else 0

    if stream_csv and st.session_state.live_running and refresh and refresh > 0:
        st.session_state.csv_pos += rows_per_tick

    if total == 0:
        df = base_df.copy()
    else:
        if st.session_state.csv_pos > total:
            if loop_csv:
                st.session_state.csv_pos = st.session_state.csv_pos % total
                if st.session_state.csv_pos == 0:
                    st.session_state.csv_pos = min(rows_per_tick, total)
            else:
                st.session_state.csv_pos = total

        end = min(st.session_state.csv_pos, total)
        start = max(0, end - window_size)
        df = base_df.iloc[start:end].copy()
        st.caption(f"📡 Streaming: showing rows **{start + 1} → {end}** of **{total}**")
else:
    df = demo_data()

df = df.copy()

# ML anomaly
if enable_ml and not df.empty:
    df = add_anomaly_scores(df, contamination=contamination)


# ----------------------------
# Detection -> alerts_df
# ----------------------------
alerts = []
for _, row in df.iterrows():
    for _, rule in edited_rules.iterrows():
        if eval_rule(rule, row):
            alerts.append({
                "time": row.get("time",""),
                "src_ip": row.get("src_ip",""),
                "rule": rule.get("name",""),
                "type": rule.get("type",""),
                "severity": rule.get("severity",""),
                "details": rule.get("desc",""),
                "ml_anomaly": bool(row.get("is_anomaly", False)),
                "anomaly_score": float(row.get("anomaly_score", 0.0)) if "anomaly_score" in row else 0.0,
            })
alerts_df = pd.DataFrame(alerts)


# ----------------------------
# KPIs
# ----------------------------
k1, k2, k3, k4 = st.columns(4)
k1.metric("Total Events (visible)", len(df))
k2.metric("Total Alerts", len(alerts_df))
k3.metric("High Severity", int((alerts_df.get("severity") == "High").sum()) if len(alerts_df) else 0)
k4.metric("Unique Source IPs", df["src_ip"].nunique() if "src_ip" in df.columns else 0)
st.divider()


# ----------------------------
# Layout: Events + Alerts
# ----------------------------
left, right = st.columns([0.58, 0.42], gap="large")

with left:
    st.subheader("📥 Incoming Events")
    st.dataframe(df, use_container_width=True, height=420)

with right:
    st.subheader("🚨 Alerts")
    if alerts_df.empty:
        st.success("No alerts triggered ✅")
    else:
        show = alerts_df.copy()
        if "severity" in show.columns:
            st.dataframe(show.style.applymap(severity_style, subset=["severity"]), use_container_width=True, height=420)
        else:
            st.dataframe(show, use_container_width=True, height=420)

st.divider()


# ----------------------------
# Charts (Matplotlib to avoid Altair/rpds issues)
# ----------------------------
st.subheader("📊 Charts")

cA, cB, cC = st.columns(3)

with cA:
    st.caption("Alerts by Severity")
    if alerts_df.empty:
        st.info("No alerts yet.")
    else:
        sev_counts = alerts_df["severity"].value_counts()
        fig = plt.figure()
        plt.bar(sev_counts.index.tolist(), sev_counts.values.tolist())
        plt.xlabel("Severity")
        plt.ylabel("Count")
        st.pyplot(fig, clear_figure=True)

with cB:
    st.caption("Top Source IPs by Alerts")
    if alerts_df.empty:
        st.info("No alerts yet.")
    else:
        ip_counts = alerts_df["src_ip"].value_counts().head(10)
        fig = plt.figure()
        plt.bar(ip_counts.index.tolist(), ip_counts.values.tolist())
        plt.xticks(rotation=45, ha="right")
        plt.xlabel("Source IP")
        plt.ylabel("Alerts")
        st.pyplot(fig, clear_figure=True)

with cC:
    st.caption("Anomaly Score (visible window)")
    if "anomaly_score" in df.columns and not df.empty:
        fig = plt.figure()
        plt.plot(df["anomaly_score"].tolist())
        plt.xlabel("Row Index")
        plt.ylabel("Anomaly Score")
        st.pyplot(fig, clear_figure=True)
    else:
        st.info("Enable ML to see anomaly score chart.")

st.divider()


# ----------------------------
# AI Explanation
# ----------------------------
st.subheader("🧠 AI Alert Explanation")

if alerts_df.empty:
    st.info("No alert selected because there are no alerts.")
else:
    alerts_df = alerts_df.reset_index(drop=True)
    pick = st.selectbox(
        "Pick an alert to explain",
        options=list(range(len(alerts_df))),
        format_func=lambda i: f"[{alerts_df.loc[i,'severity']}] {alerts_df.loc[i,'src_ip']} → {alerts_df.loc[i,'rule']} @ {alerts_df.loc[i,'time']}",
    )
    alert_row = alerts_df.loc[int(pick)].to_dict()

    st.write(
        f"**Source IP:** `{alert_row.get('src_ip')}`  |  **Rule:** `{alert_row.get('rule')}`  |  **Severity:** `{alert_row.get('severity')}`"
    )

    with st.spinner("Generating explanation..."):
        exp = explain_alert(alert_row)

    if exp.ok:
        st.markdown(exp.message)  # keep safe: no unsafe_allow_html
        if getattr(exp, "used_ai", False):
            st.caption(f"✅ AI used ({getattr(exp, 'model', 'model')})")
        else:
            st.caption("ℹ️ Template explanation (set OPENAI_API_KEY for AI)")
    else:
        st.error(exp.message)

st.divider()


# ----------------------------
# Response Actions (Firewall)
# ----------------------------
st.subheader("🧱 Response Actions (IP Blocking)")

if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = set()

dry_run = st.sidebar.checkbox("Dry-run firewall (recommended)", value=True)
allow_real = st.sidebar.checkbox("Enable REAL blocking", value=False, disabled=not is_admin())
backend = st.sidebar.selectbox("Firewall backend", ["auto", "windows_defender"], index=0)

ip_list = sorted(df["src_ip"].dropna().unique().tolist()) if "src_ip" in df.columns else []
selected_ip = st.selectbox("Select Source IP", ip_list if ip_list else ["N/A"])

b1, b2, b3 = st.columns([1, 1, 1])

with b1:
    if st.button("🚫 Block IP", use_container_width=True, disabled=not is_admin()):
        if not is_valid_ip(selected_ip):
            st.error("Invalid IP.")
        else:
            # CSRF check (report + safety)
            if not require_csrf(csrf_token):
                st.error("CSRF check failed.")
            else:
                res = block_ip(selected_ip, allow_real=allow_real, dry_run=dry_run, backend=backend)
                if res.ok:
                    st.session_state.blocked_ips.add(selected_ip)
                    st.success(res.message)
                else:
                    st.error(res.message)
                if res.command:
                    st.code(res.command)

with b2:
    if st.button("✅ Unblock IP", use_container_width=True, disabled=not is_admin()):
        if not is_valid_ip(selected_ip):
            st.error("Invalid IP.")
        else:
            if not require_csrf(csrf_token):
                st.error("CSRF check failed.")
            else:
                res = unblock_ip(selected_ip, allow_real=allow_real, dry_run=dry_run, backend=backend)
                if res.ok:
                    st.session_state.blocked_ips.discard(selected_ip)
                    st.success(res.message)
                else:
                    st.error(res.message)
                if res.command:
                    st.code(res.command)

with b3:
    if st.button("📜 Show IDS Firewall Rules", use_container_width=True):
        res = list_ids_rules()
        if res.ok:
            st.code(res.message)
        else:
            st.error(res.message)

st.caption(
    "Blocked IPs (session): "
    + (", ".join(sorted(st.session_state.blocked_ips)) if st.session_state.blocked_ips else "None")
)

if not is_admin():
    st.warning("Viewer role: blocking disabled.")

with st.expander("📘 How this IDS works (for lab viva)"):
    st.markdown(
        """
**Flow**
1) Data Source → Demo events or CSV live stream  
2) Detection → Rules apply on each row (SAFE AST evaluator)  
3) ML Layer → Isolation Forest highlights anomalies  
4) Alerts → severity + rule + source IP  
5) Response → Admin can block/unblock (Dry-run by default)

**Security Controls**
- RBAC: admin-only response actions  
- Session security: login required  
- Safe rule evaluation: no raw eval  
- IP validation before firewall calls  
- CSRF token check for sensitive actions  
- Charts use Matplotlib (no Altair dependency)
"""
    )


# ----------------------------
# Timer-based auto refresh (ONLY when running)
# ----------------------------
render_header()

if refresh and refresh > 0 and st.session_state.live_running:
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=refresh * 1000, key="ids_autorefresh")
    except Exception:
        time.sleep(refresh)
        st.rerun()