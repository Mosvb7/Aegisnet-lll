"""
scandash.py  —  AegisNet SOC Dashboard  (v4)
============================================
Run:   streamlit run scandash.py

New in v4:
  [NEW] Incidents tab — deduplicated view (1 row per IP+attack, with hit counter)
  [NEW] Incident drill-down — click any IP to see full timeline + score history
  [NEW] Threat Score History chart — risk score over time per IP
  [NEW] Notification Settings panel — configure email + Telegram alerts from UI
  [NEW] Test Notification button

Dependencies:
  pip install streamlit streamlit-autorefresh streamlit-folium plotly folium requests pandas
"""

import json
import sqlite3
import time

import folium
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from streamlit_folium import st_folium
import os
import hmac
import hashlib
import io

# ── CONFIG ────────────────────────────────────────────────────────────────────

ENGINE   = "http://127.0.0.1:5050"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "alert.db")

st.set_page_config(
    page_title="AegisNet SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
st_autorefresh(interval=5000, key="ar")

# ── AUTHENTICATION ────────────────────────────────────────────────────────────

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DASH_USER  = os.getenv("DASH_USER",  "msvb")
DASH_USER2 = os.getenv("DASH_USER2", "administrator/sdn#")
DASH_USER3 = os.getenv("DASH_USER3", "admin8882")

DASH_CODE_HASH  = os.getenv("DASH_CODE_HASH",  hashlib.sha256("9898".encode()).hexdigest())
DASH_CODE_HASH2 = os.getenv("DASH_CODE_HASH2", hashlib.sha256("1110".encode()).hexdigest())
DASH_CODE_HASH3 = os.getenv("DASH_CODE_HASH3", hashlib.sha256("rak4".encode()).hexdigest())

_USER_HASH_MAP = {
    DASH_USER:  DASH_CODE_HASH,
    DASH_USER2: DASH_CODE_HASH2,
    DASH_USER3: DASH_CODE_HASH3,
}

def check_login(username: str, code: str) -> bool:
    expected_hash = _USER_HASH_MAP.get(username)
    if not expected_hash:
        return False
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    return hmac.compare_digest(code_hash, expected_hash)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "last_alert_count" not in st.session_state:
    st.session_state.last_alert_count = 0

if not st.session_state.authenticated:
    st.markdown("""
    <style>
    .login-box{max-width:400px;margin:80px auto;padding:2rem;
               background:#0d1117;border:1px solid #30363d;border-radius:12px;}
    </style>
    <div class="login-box">
    <h2 style="color:#58a6ff;margin-bottom:1rem">🛡️ AegisNet SOC</h2>
    </div>
    """, unsafe_allow_html=True)
    username = st.text_input("Username")
    code     = st.text_input("Access code", type="password")
    if st.button("Login", type="primary"):
        if check_login(username, code):
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Login failed — invalid credentials")
    st.stop()

# ── DB BOOTSTRAP ─────────────────────────────────────────────────────────────

def ensure_dashboard_db() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, destination_ip TEXT,
        attack_type TEXT, severity TEXT, risk_score INTEGER,
        lat REAL, lon REAL, extra TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE, reason TEXT, timestamp TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS login_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, service TEXT, username TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS browsing_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, destination_ip TEXT,
        host TEXT, domain TEXT, protocol TEXT, action TEXT, url_hint TEXT
    )""")
    con.commit()
    con.close()

ensure_dashboard_db()

# ── DATA HELPERS ──────────────────────────────────────────────────────────────

def load_alerts() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df  = pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 500", con)
        con.close()
        if "extra" in df.columns and not df.empty:
            def _expand(v):
                try: return json.loads(v or "{}")
                except: return {}
            extra = pd.json_normalize(df["extra"].apply(_expand).tolist())
            if not extra.empty:
                for col in ["isp","asn","country","os_guess","scan_type","pps","login_fails"]:
                    if col in extra.columns:
                        df[col] = extra[col]
        return df
    except Exception as e:
        st.error(f"DB error: {e}")
        return pd.DataFrame()

def load_blocked() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df  = pd.read_sql_query("SELECT * FROM blocked_ips ORDER BY id DESC", con)
        con.close()
        return df
    except Exception as e:
        st.error(f"DB error: {e}")
        return pd.DataFrame()

def load_login_events() -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        df  = pd.read_sql_query(
            "SELECT * FROM login_events ORDER BY id DESC LIMIT 200", con)
        con.close()
        return df
    except Exception:
        return pd.DataFrame()

def load_browsing(ip: str = "", limit: int = 300) -> pd.DataFrame:
    try:
        con = sqlite3.connect(DB_PATH)
        if ip:
            df = pd.read_sql_query(
                "SELECT * FROM browsing_activity WHERE source_ip=?"
                " ORDER BY id DESC LIMIT ?", con, params=(ip, limit))
        else:
            df = pd.read_sql_query(
                "SELECT * FROM browsing_activity ORDER BY id DESC LIMIT ?",
                con, params=(limit,))
        con.close()
        return df
    except Exception:
        return pd.DataFrame()

def load_devices_live() -> list:
    try:
        r = requests.get(f"{ENGINE}/devices_live", timeout=3)
        return r.json()
    except Exception:
        return []

def load_incidents() -> pd.DataFrame:
    """Load deduplicated incidents — one row per (IP, attack_type)."""
    try:
        con = sqlite3.connect(DB_PATH)
        df  = pd.read_sql_query(
            "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 500", con)
        con.close()
        return df
    except Exception:
        return pd.DataFrame()

def load_risk_history(ip: str = "") -> pd.DataFrame:
    """Load risk score history for one IP or all IPs."""
    try:
        con = sqlite3.connect(DB_PATH)
        if ip:
            df = pd.read_sql_query(
                "SELECT * FROM risk_history WHERE source_ip=? ORDER BY id ASC",
                con, params=(ip,))
        else:
            df = pd.read_sql_query(
                "SELECT * FROM risk_history ORDER BY id ASC LIMIT 2000", con)
        con.close()
        return df
    except Exception:
        return pd.DataFrame()

def eng(path: str, **kw):
    try:
        return requests.get(f"{ENGINE}{path}", timeout=3, **kw).json()
    except Exception:
        return {}

def eng_post(path: str, payload: dict):
    try:
        return requests.post(f"{ENGINE}{path}", json=payload, timeout=3).json()
    except Exception:
        return {}

def engine_latency() -> str:
    """Ping the engine and return latency string."""
    try:
        t0 = time.time()
        requests.get(f"{ENGINE}/status", timeout=2)
        ms = int((time.time() - t0) * 1000)
        return f"{ms} ms"
    except Exception:
        return "offline"

def ip_threat_intel(ip: str) -> dict:
    """Fetch threat intel for an IP from ip-api.com (free, no key needed)."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,"
            f"city,isp,as,proxy,hosting,mobile,lat,lon,org",
            timeout=4
        ).json()
        return r if r.get("status") == "success" else {}
    except Exception:
        return {}

# ── SEVERITY COLOUR ───────────────────────────────────────────────────────────

_SEV_COLOR = {
    "High":   "background-color:#7a1c1c;color:#ffd6d6",
    "Medium": "background-color:#5a3a00;color:#ffe4a0",
    "Low":    "background-color:#1a3a1a;color:#c6f0c6",
}
def colour_row(row):
    s = _SEV_COLOR.get(row.get("severity",""),"")
    return [s]*len(row)

# ── HEADER ────────────────────────────────────────────────────────────────────

st.markdown(
    "<h1 style='margin-bottom:0'>🛡️ AegisNet SOC Dashboard</h1>"
    "<p style='color:gray;margin-top:2px'>Real-time IDS/IPS  —  scandash.py v3</p>",
    unsafe_allow_html=True
)

# Engine status bar
t_start  = time.time()
status   = eng("/status")
latency  = int((time.time() - t_start) * 1000)

if status:
    iptables  = "ON" if status.get("iptables") else "OFF (no root)"
    wl_count  = len(status.get("whitelist", []))
    st.success(
        f"🟢 Engine online  |  Interface: `{status.get('interface','?')}`  |  "
        f"Geo: `{status.get('geo_backend','?')}`  |  iptables: `{iptables}`  |  "
        f"Queue: `{status.get('queue_size',0)}`  |  "
        f"Devices: `{status.get('arp_devices',0)}`  |  "
        f"Whitelist: `{wl_count}` entries  |  "
        f"Latency: `{latency} ms`"
    )
else:
    st.error("🔴 Engine offline — start realengine.py first.")

# ── LOAD DATA ─────────────────────────────────────────────────────────────────

alerts_df    = load_alerts()
blocked_df   = load_blocked()
login_df     = load_login_events()
incidents_df = load_incidents()
devices_raw  = eng("/devices") or []
devices_df   = pd.DataFrame(devices_raw) if devices_raw else pd.DataFrame()
devices_live = load_devices_live()

# ── NEW HIGH ALERT SOUND ──────────────────────────────────────────────────────
# Inject a small JS beep when new High-severity alerts appear

if not alerts_df.empty:
    high_now = len(alerts_df[alerts_df["severity"] == "High"])
    if high_now > st.session_state.last_alert_count:
        st.markdown("""
        <script>
        (function(){
          var ctx=new (window.AudioContext||window.webkitAudioContext)();
          var osc=ctx.createOscillator();
          var gain=ctx.createGain();
          osc.connect(gain); gain.connect(ctx.destination);
          osc.frequency.value=880; osc.type='square';
          gain.gain.setValueAtTime(0.3,ctx.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+0.4);
          osc.start(ctx.currentTime); osc.stop(ctx.currentTime+0.4);
        })();
        </script>
        """, unsafe_allow_html=True)
    st.session_state.last_alert_count = high_now

# ── METRICS ───────────────────────────────────────────────────────────────────

st.subheader("📊 Live Summary")
c1,c2,c3,c4,c5,c6 = st.columns(6)
if not alerts_df.empty:
    n_high   = len(alerts_df[alerts_df["severity"]=="High"])
    n_med    = len(alerts_df[alerts_df["severity"]=="Medium"])
    n_low    = len(alerts_df[alerts_df["severity"]=="Low"])
    c1.metric("🚨 High",   n_high)
    c2.metric("⚠️ Medium", n_med)
    c3.metric("✅ Low",    n_low)
else:
    n_high = n_med = n_low = 0
    c1.metric("🚨 High",0); c2.metric("⚠️ Medium",0); c3.metric("✅ Low",0)
c4.metric("🚫 Blocked IPs",  len(blocked_df))
c5.metric("🖥️ LAN Devices",   len(devices_df))
c6.metric("🔐 Login Fails",  len(login_df))

# ── TABS ──────────────────────────────────────────────────────────────────────

t1,t2,t3,t4,t5,t6,t7,t8,t9 = st.tabs([
    f"🚨 Alerts ({n_high+n_med+n_low})",
    f"📁 Incidents ({len(incidents_df)})",
    "🌍 Geo Map",
    "🖥️ Devices",
    "🌐 Network Activity",
    f"🔐 Auth Logs ({len(login_df)})",
    "🔎 Threat Intel",
    "🔔 Notifications",
    "🛠️ Admin",
])

# ── TAB 1: ALERTS ────────────────────────────────────────────────────────────

with t1:
    # Coloured timeline per attack type
    st.subheader("📈 Threat Timeline — coloured by attack type")
    if not alerts_df.empty and "timestamp" in alerts_df.columns:
        try:
            ts_df = alerts_df.copy()
            ts_df["timestamp"] = pd.to_datetime(ts_df["timestamp"])
            # Pivot: index=time_bucket, columns=attack_type, values=count
            ts_df = ts_df.set_index("timestamp").sort_index()
            pivot = (
                ts_df.groupby([pd.Grouper(freq="1min"), "attack_type"])
                     .size()
                     .reset_index(name="count")
            )
            if not pivot.empty:
                fig_tl = px.area(
                    pivot, x="timestamp", y="count", color="attack_type",
                    title="Alerts per minute by type",
                    color_discrete_sequence=px.colors.qualitative.Bold,
                )
                fig_tl.update_layout(
                    height=280, margin=dict(t=30,b=0,l=0,r=0),
                    legend_title_text="Attack Type"
                )
                st.plotly_chart(fig_tl, use_container_width=True)
        except Exception:
            st.info("Not enough data yet for timeline.")

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("⚔️ Attack Type Breakdown")
        if not alerts_df.empty:
            tc = alerts_df["attack_type"].value_counts()
            st.plotly_chart(
                px.pie(values=tc.values, names=tc.index,
                       color_discrete_sequence=px.colors.sequential.RdBu),
                use_container_width=True
            )

    with col_b:
        st.subheader("🔍 Scan Type Breakdown")
        scan_data = eng("/scan_types")
        if scan_data:
            sdf = pd.DataFrame(scan_data)
            if "attack_type" in sdf.columns and "hits" in sdf.columns:
                sc = sdf.groupby("attack_type")["hits"].sum()
                st.bar_chart(sc)
        else:
            if not alerts_df.empty and "attack_type" in alerts_df.columns:
                scans = alerts_df[alerts_df["attack_type"].str.contains("Scan", na=False)]
                if not scans.empty:
                    st.bar_chart(scans.groupby("attack_type").size().sort_values(ascending=False))
                else:
                    st.info("No scan activity yet.")

    col_c, col_d = st.columns(2)

    with col_c:
        st.subheader("💻 Top Attacker IPs")
        if not alerts_df.empty:
            top = (alerts_df.groupby("source_ip").size()
                            .sort_values(ascending=False).head(10))
            st.bar_chart(top)

    with col_d:
        # NEW: Top attacked destination ports
        st.subheader("🎯 Top Targeted Ports")
        if not alerts_df.empty:
            try:
                # Extract dst_port from extra JSON if available
                def get_dst_port(extra_str):
                    try:
                        d = json.loads(extra_str or "{}")
                        return d.get("dst_port", None)
                    except:
                        return None

                if "extra" in alerts_df.columns:
                    port_series = alerts_df["extra"].apply(get_dst_port).dropna()
                    port_series = port_series[port_series > 0]
                    if not port_series.empty:
                        port_counts = port_series.value_counts().head(10)
                        # Map well-known ports to names
                        port_names = {
                            22:"SSH(22)", 80:"HTTP(80)", 443:"HTTPS(443)",
                            21:"FTP(21)", 23:"Telnet(23)", 25:"SMTP(25)",
                            3389:"RDP(3389)", 3306:"MySQL(3306)",
                            5432:"PgSQL(5432)", 6379:"Redis(6379)"
                        }
                        port_counts.index = [port_names.get(int(p), str(int(p))) for p in port_counts.index]
                        st.bar_chart(port_counts)
                    else:
                        st.info("Port data not available yet.")
                else:
                    st.info("No port data in alerts.")
            except Exception:
                st.info("Port analysis unavailable.")

    st.subheader("📋 Alert Log")
    if alerts_df.empty:
        st.info("No alerts yet.")
    else:
        # Filter controls
        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            sev_filter = st.multiselect(
                "Severity", ["High","Medium","Low"],
                default=["High","Medium","Low"], key="sev_filter"
            )
        with fcol2:
            attack_types = alerts_df["attack_type"].dropna().unique().tolist()
            type_filter  = st.multiselect(
                "Attack Type", attack_types, default=attack_types, key="type_filter"
            )
        with fcol3:
            # CSV export
            show_cols = [c for c in
                ["timestamp","source_ip","destination_ip","attack_type",
                 "severity","risk_score","country","isp","asn",
                 "os_guess","scan_type","lat","lon"]
                if c in alerts_df.columns]
            filtered_for_export = alerts_df[
                alerts_df["severity"].isin(sev_filter) &
                alerts_df["attack_type"].isin(type_filter)
            ][show_cols]
            csv_buf = io.StringIO()
            filtered_for_export.to_csv(csv_buf, index=False)
            st.download_button(
                "⬇️ Export CSV",
                data=csv_buf.getvalue(),
                file_name="aegisnet_alerts.csv",
                mime="text/csv",
                key="export_csv"
            )

        filtered_df = alerts_df[
            alerts_df["severity"].isin(sev_filter) &
            alerts_df["attack_type"].isin(type_filter)
        ]
        st.dataframe(
            filtered_df[show_cols].style.apply(colour_row, axis=1),
            use_container_width=True
        )

# ── TAB 2: INCIDENTS ─────────────────────────────────────────────────────────

with t2:
    st.subheader("📁 Incidents — Deduplicated View")
    st.caption(
        "One row per (Source IP + Attack Type). "
        "Hit Count shows how many times this exact threat was seen. "
        "Click an IP in the selector below to drill into its full timeline."
    )

    if incidents_df.empty:
        st.info("No incidents yet — alerts will appear here grouped by IP and attack type.")
    else:
        # Summary metrics
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Unique Attacker IPs",
                   incidents_df["source_ip"].nunique() if "source_ip" in incidents_df.columns else 0)
        mc2.metric("Total Incidents",     len(incidents_df))
        mc3.metric("Total Hit Count",
                   int(incidents_df["hit_count"].sum()) if "hit_count" in incidents_df.columns else 0)
        mc4.metric("Active High Severity",
                   len(incidents_df[incidents_df["severity"]=="High"]) if "severity" in incidents_df.columns else 0)

        # Colour and display
        show_cols = [c for c in
            ["source_ip","attack_type","severity","risk_score","hit_count",
             "first_seen","last_seen","extra"]
            if c in incidents_df.columns]

        st.dataframe(
            incidents_df[show_cols].style.apply(colour_row, axis=1),
            use_container_width=True
        )

        st.divider()

        # ── IP DRILL-DOWN ─────────────────────────────────────────────────────
        st.subheader("🔍 IP Incident Drill-Down")
        all_ips = sorted(incidents_df["source_ip"].dropna().unique().tolist()) \
            if "source_ip" in incidents_df.columns else []

        sel_ip = st.selectbox(
            "Select source IP to investigate",
            options=["— select —"] + all_ips,
            key="incident_ip_sel"
        )

        if sel_ip and sel_ip != "— select —":
            ip_incidents = incidents_df[incidents_df["source_ip"] == sel_ip]
            ip_alerts    = alerts_df[alerts_df["source_ip"] == sel_ip] \
                if not alerts_df.empty else pd.DataFrame()

            col_dd1, col_dd2, col_dd3, col_dd4 = st.columns(4)
            col_dd1.metric("Attack Types",  len(ip_incidents))
            col_dd2.metric("Total Hits",
                           int(ip_incidents["hit_count"].sum()) if "hit_count" in ip_incidents.columns else 0)
            col_dd3.metric("Max Risk Score",
                           int(ip_incidents["risk_score"].max()) if "risk_score" in ip_incidents.columns else 0)
            col_dd4.metric("Raw Alert Rows", len(ip_alerts))

            # Incident summary for this IP
            st.markdown(f"**Incident summary for `{sel_ip}`**")
            st.dataframe(
                ip_incidents[show_cols].style.apply(colour_row, axis=1),
                use_container_width=True
            )

            # ── Threat Score History Chart ─────────────────────────────────────
            st.subheader(f"📈 Threat Score History — {sel_ip}")
            rh_df = load_risk_history(ip=sel_ip)
            if not rh_df.empty and "timestamp" in rh_df.columns:
                try:
                    rh_df["timestamp"] = pd.to_datetime(rh_df["timestamp"])
                    fig_rh = px.line(
                        rh_df, x="timestamp", y="risk_score",
                        color="attack_type",
                        title=f"Risk score over time for {sel_ip}",
                        color_discrete_sequence=px.colors.qualitative.Bold,
                        markers=True
                    )
                    fig_rh.add_hline(y=88, line_dash="dash",
                                     line_color="red",   annotation_text="High threshold (88)")
                    fig_rh.add_hline(y=70, line_dash="dash",
                                     line_color="orange", annotation_text="Medium threshold (70)")
                    fig_rh.update_layout(
                        height=320, margin=dict(t=40,b=0,l=0,r=0),
                        yaxis_range=[0,100]
                    )
                    st.plotly_chart(fig_rh, use_container_width=True)
                except Exception as e:
                    st.info(f"Score history chart error: {e}")
            else:
                st.info("No score history yet for this IP.")

            # ── Full raw alert timeline ────────────────────────────────────────
            if not ip_alerts.empty:
                st.subheader(f"📋 Full Alert Timeline — {sel_ip}")
                tl_cols = [c for c in
                    ["timestamp","attack_type","severity","risk_score",
                     "destination_ip","scan_type","country","isp"]
                    if c in ip_alerts.columns]
                st.dataframe(
                    ip_alerts[tl_cols].style.apply(colour_row, axis=1),
                    use_container_width=True
                )

# ── TAB 3: GEO MAP ───────────────────────────────────────────────────────────

with t3:
    st.subheader("🌍 Real Attacker Geolocation Map")

    map_mode = st.radio(
        "Map style", ["Scatter (dot per alert)", "Heatmap (density)"],
        horizontal=True, key="map_mode"
    )

    if not alerts_df.empty and "lat" in alerts_df.columns:
        # ── FIX: Use & (AND) so only rows where BOTH lat AND lon are 0 are removed.
        # Previously `|` (OR) was being used but the logic was still correct.
        # The real fix is handling LAN IPs specially and clamping risk_score.
        geo_df = alerts_df.copy()
        geo_df = geo_df.dropna(subset=["lat","lon"])
        # Separate external (non-zero) from internal (0,0 or LAN coords)
        # LAN IPs all resolve to self-location which may legitimately be non-zero.
        # We filter out only rows where BOTH are exactly zero (no geo data at all).
        geo_df = geo_df[~((geo_df["lat"] == 0) & (geo_df["lon"] == 0))]

        if not geo_df.empty:
            # FIX: Clamp risk_score so plotly scatter never gets size=0
            geo_df["_size"] = geo_df["risk_score"].fillna(1).clip(lower=4)

            if map_mode == "Scatter (dot per alert)":
                hover = [c for c in ["attack_type","risk_score","timestamp",
                                      "isp","country","os_guess"]
                         if c in geo_df.columns]
                fig = px.scatter_mapbox(
                    geo_df, lat="lat", lon="lon",
                    color="severity",
                    # FIX: use _size column (clamped) instead of raw risk_score
                    size="_size",
                    size_max=18,
                    hover_name="source_ip",
                    hover_data=hover,
                    color_discrete_map={"High":"red","Medium":"orange","Low":"green"},
                    zoom=1,
                    # FIX: use open-street-map — works without any Mapbox token
                    mapbox_style="open-street-map"
                )
                fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, height=520)
                st.plotly_chart(fig, use_container_width=True)

            else:  # Heatmap
                fig = px.density_mapbox(
                    geo_df, lat="lat", lon="lon",
                    z="risk_score", radius=20,
                    zoom=1, height=520,
                    mapbox_style="open-street-map",
                    color_continuous_scale="YlOrRd",
                    title="Alert density heatmap (colour = cumulative risk)"
                )
                fig.update_layout(margin={"r":0,"t":30,"l":0,"b":0})
                st.plotly_chart(fig, use_container_width=True)

            # Stats below the map
            st.caption(
                f"Showing {len(geo_df)} geo-located alerts. "
                f"IPs with no location data (both lat & lon = 0) are hidden."
            )

            # Country breakdown
            if "country" in geo_df.columns:
                country_counts = geo_df["country"].value_counts().head(15)
                if not country_counts.empty:
                    st.subheader("🌐 Alerts by Country")
                    st.bar_chart(country_counts)
        else:
            st.info(
                "No geo-located alerts yet.\n\n"
                "All source IPs resolved to 0,0 — this usually means:\n"
                "- The engine's GeoIP lookup failed at startup (check ipinfo.io connectivity)\n"
                "- All traffic so far is from your LAN (private IPs show your own location)\n\n"
                "Try running `curl ipinfo.io/json` in your terminal to verify geolocation works."
            )
    else:
        st.info("No alert data yet.")

# ── TAB 3: DEVICES ───────────────────────────────────────────────────────────

with t3:
    st.subheader("🖥️ LAN Devices (ARP + OS Fingerprint)")
    if devices_df.empty:
        st.info("No devices found. Run realengine.py as root for ARP scan.")
    else:
        st.dataframe(devices_df, use_container_width=True)

        if "ip" in devices_df.columns and "risk_score" in devices_df.columns:
            st.subheader("⚠️ Device Risk Levels")
            st.bar_chart(devices_df.set_index("ip")["risk_score"])

        # FIX: Only add markers for devices that actually have valid coordinates.
        # LAN devices get the machine's own lat/lon from ipinfo, which is valid.
        # Only skip markers where lat==0 AND lon==0 (no geo data at all).
        st.subheader("🗺️ Device Map")
        m = folium.Map(location=[20, 0], zoom_start=2)
        mapped = 0
        for dev in devices_raw:
            lat  = dev.get("lat", 0)
            lon  = dev.get("lon", 0)
            risk = dev.get("risk_score", 0)

            # FIX: skip only truly zero coordinates
            if lat == 0 and lon == 0:
                continue

            col = "red" if risk >= 70 else ("orange" if risk >= 40 else "green")
            folium.CircleMarker(
                location=[lat, lon],
                radius=8,
                color=col, fill=True, fill_color=col,
                popup=(
                    f"<b>IP:</b> {dev.get('ip','?')}<br>"
                    f"<b>MAC:</b> {dev.get('mac','?')}<br>"
                    f"<b>Host:</b> {dev.get('hostname','?')}<br>"
                    f"<b>OS:</b> {dev.get('os_guess','?')}<br>"
                    f"<b>Risk:</b> {risk}"
                ),
                tooltip=dev.get("ip","?")
            ).add_to(m)
            mapped += 1

        if mapped > 0:
            st_folium(m, width=700, height=400)
        else:
            st.info(
                "No device coordinates available yet.\n\n"
                "LAN devices show your own location (from ipinfo.io). "
                "If geolocation failed at startup, restart realengine.py "
                "with a working internet connection."
            )

# ── TAB 4: NETWORK ACTIVITY ──────────────────────────────────────────────────

with t5:
    st.subheader("🌐 Connected Devices & Browsing Activity")
    st.caption("Live view of every LAN device and what they are browsing (DNS · HTTP · HTTPS SNI)")

    if not devices_live:
        st.info(
            "No devices discovered yet.\n\n"
            "Make sure **realengine.py** is running as root so ARP scan and "
            "the browsing sniffer can operate.\n\n"
            "The browsing sniffer captures DNS queries, HTTP Host headers, "
            "and HTTPS SNI fields — it does **not** decrypt traffic."
        )
    else:
        total_req = sum(d.get("total_requests", 0) for d in devices_live)
        col_d1, col_d2, col_d3 = st.columns(3)
        col_d1.metric("🖥️ Devices Online", len(devices_live))
        col_d2.metric("🌍 Total DNS/HTTP Requests", total_req)
        active = sum(1 for d in devices_live if d.get("total_requests", 0) > 0)
        col_d3.metric("📡 Actively Browsing", active)

        st.divider()

        devices_sorted = sorted(
            devices_live, key=lambda d: d.get("total_requests", 0), reverse=True
        )
        all_ips = [d["ip"] for d in devices_sorted]
        filter_ip = st.selectbox(
            "🔎 Filter by device IP (or show all)",
            options=["All devices"] + all_ips
        )
        if filter_ip != "All devices":
            devices_sorted = [d for d in devices_sorted if d["ip"] == filter_ip]

        for dev in devices_sorted:
            ip       = dev.get("ip", "?")
            mac      = dev.get("mac", "?")
            hostname = dev.get("hostname") or "—"
            os_g     = dev.get("os_guess", "Unknown")
            risk     = dev.get("risk_score", 0)
            total_r  = dev.get("total_requests", 0)
            domains  = dev.get("top_domains", [])
            last_s   = dev.get("last_seen", "")

            risk_color = (
                "#7a1c1c" if risk >= 70 else "#5a3a00" if risk >= 40 else "#1a3a1a"
            )
            risk_label = (
                "🔴 High Risk" if risk >= 70 else "🟡 Medium" if risk >= 40 else "🟢 Low Risk"
            )

            with st.expander(
                f"{'🔴' if risk>=70 else '🟡' if risk>=40 else '🟢'}  "
                f"**{ip}**  —  {hostname}  |  {os_g}  |  "
                f"{total_r} requests  |  {risk_label}",
                expanded=(filter_ip != "All devices")
            ):
                c1, c2, c3, c4 = st.columns(4)
                c1.markdown(f"**IP**\n\n`{ip}`")
                c2.markdown(f"**MAC**\n\n`{mac}`")
                c3.markdown(f"**Hostname**\n\n{hostname}")
                c4.markdown(f"**Last Seen**\n\n{last_s}")

                st.markdown(
                    f"**OS Guess:** {os_g} &nbsp;&nbsp; "
                    f"**Risk Score:** `{risk}` &nbsp;&nbsp; {risk_label}"
                )

                if domains:
                    st.markdown("**🌐 Top Browsed Domains**")
                    dom_df = pd.DataFrame(domains)

                    def _proto_badge(p):
                        colors = {"DNS":"#1a5276","HTTP":"#7d6608","HTTPS":"#1e8449"}
                        c = colors.get(p, "#555")
                        return (f'<span style="background:{c};color:#fff;'
                                f'padding:2px 7px;border-radius:4px;'
                                f'font-size:0.8em">{p}</span>')

                    dom_df["protocol_badge"] = dom_df["protocol"].apply(_proto_badge)
                    st.markdown(
                        dom_df[["domain","protocol_badge","visits","last_visit"]]
                        .rename(columns={
                            "domain":"Domain","protocol_badge":"Protocol",
                            "visits":"Visits","last_visit":"Last Visit"
                        })
                        .to_html(escape=False, index=False),
                        unsafe_allow_html=True
                    )
                    if len(dom_df) > 1:
                        st.bar_chart(dom_df.set_index("domain")["visits"],
                                     use_container_width=True)
                else:
                    st.info("No browsing activity captured yet for this device.")

                st.caption(f"Load full raw feed for {ip}")
                if st.button(f"📋 Show raw request log  [{ip}]", key=f"raw_{ip}"):
                    raw_df = load_browsing(ip=ip, limit=200)
                    if raw_df.empty:
                        st.warning("No records found.")
                    else:
                        show_cols = [c for c in
                            ["timestamp","domain","protocol","query_type",
                             "dst_ip","dst_port","url_hint"]
                            if c in raw_df.columns]
                        st.dataframe(raw_df[show_cols], use_container_width=True)

        st.divider()

        st.subheader("📈 Global Browsing Traffic Timeline")
        browse_df = load_browsing(limit=1000)
        if not browse_df.empty and "timestamp" in browse_df.columns:
            try:
                browse_df["timestamp"] = pd.to_datetime(browse_df["timestamp"])
                timeline = (
                    browse_df.set_index("timestamp")
                    .sort_index()
                    .resample("1min")["id"].count()
                    .reset_index()
                )
                timeline.columns = ["time","requests"]
                st.line_chart(timeline.set_index("time")["requests"])
            except Exception:
                st.info("Not enough data yet for timeline.")
        else:
            st.info("No browsing data captured yet.")

        if not browse_df.empty and "protocol" in browse_df.columns:
            st.subheader("🔌 Protocol Breakdown")
            col_p1, col_p2 = st.columns(2)
            with col_p1:
                proto_counts = browse_df["protocol"].value_counts()
                st.plotly_chart(
                    px.pie(values=proto_counts.values, names=proto_counts.index,
                           title="By Protocol",
                           color_discrete_map={
                               "DNS":"#1a5276","HTTP":"#b7950b","HTTPS":"#1e8449"
                           }),
                    use_container_width=True
                )
            with col_p2:
                if "source_ip" in browse_df.columns:
                    top_talkers = browse_df["source_ip"].value_counts().head(8)
                    st.plotly_chart(
                        px.bar(x=top_talkers.index, y=top_talkers.values,
                               labels={"x":"Device IP","y":"Requests"},
                               title="Most Active Devices"),
                        use_container_width=True
                    )

        if not browse_df.empty and "domain" in browse_df.columns:
            st.subheader("🏆 Top 20 Domains Across All Devices")
            top_domains = browse_df["domain"].value_counts().head(20)
            st.bar_chart(top_domains)

# ── TAB 5: AUTH LOGS ─────────────────────────────────────────────────────────

with t5:
    st.subheader("🔐 Login Failure Events (from logwatch.py)")
    if login_df.empty:
        st.info(
            "No login events yet.\n\n"
            "Make sure logwatch.py is running:  `sudo python logwatch.py`"
        )
    else:
        st.caption(f"Last {len(login_df)} events (most recent first)")
        st.dataframe(login_df, use_container_width=True)

        st.subheader("🔑 Top Brute Force Sources")
        top_bf = (login_df.groupby("source_ip").size()
                          .sort_values(ascending=False).head(10))
        st.bar_chart(top_bf)

        if "service" in login_df.columns:
            st.subheader("🔌 Targeted Services")
            svc = login_df["service"].value_counts()
            st.bar_chart(svc)

# ── TAB 6: THREAT INTELLIGENCE (NEW) ─────────────────────────────────────────

with t7:
    st.subheader("🔎 IP Threat Intelligence")
    st.caption(
        "Live lookup via ip-api.com — shows location, ISP, ASN, and whether "
        "the IP is a proxy, hosting provider, or mobile endpoint."
    )

    # Quick-select from recent alert IPs
    if not alerts_df.empty and "source_ip" in alerts_df.columns:
        recent_ips = alerts_df["source_ip"].dropna().unique().tolist()[:30]
    else:
        recent_ips = []

    col_ti1, col_ti2 = st.columns([2, 1])
    with col_ti1:
        lookup_ip = st.text_input(
            "Enter IP address to investigate",
            placeholder="e.g. 185.220.101.1",
            key="ti_ip"
        )
    with col_ti2:
        if recent_ips:
            quick_pick = st.selectbox(
                "Or pick from recent attackers",
                options=["—"] + recent_ips,
                key="ti_quick"
            )
            if quick_pick != "—":
                lookup_ip = quick_pick

    if st.button("🔍 Lookup", key="ti_lookup") and lookup_ip:
        with st.spinner(f"Looking up {lookup_ip}..."):
            intel = ip_threat_intel(lookup_ip)

        if intel:
            st.success(f"Results for **{lookup_ip}**")

            flags = []
            if intel.get("proxy"):   flags.append("🚨 **PROXY/VPN**")
            if intel.get("hosting"): flags.append("🖥️ **HOSTING/DC**")
            if intel.get("mobile"):  flags.append("📱 **MOBILE**")
            if flags:
                st.warning("  |  ".join(flags))

            ti_cols = st.columns(4)
            ti_cols[0].metric("Country",    intel.get("country","?"))
            ti_cols[1].metric("Region",     intel.get("regionName","?"))
            ti_cols[2].metric("City",       intel.get("city","?"))
            ti_cols[3].metric("ISP",        intel.get("isp","?"))

            ti_cols2 = st.columns(4)
            ti_cols2[0].metric("ASN",       intel.get("as","?"))
            ti_cols2[1].metric("Org",       intel.get("org","?"))
            ti_cols2[2].metric("Latitude",  str(intel.get("lat","?")))
            ti_cols2[3].metric("Longitude", str(intel.get("lon","?")))

            # Show this IP's alert history from our DB
            if not alerts_df.empty:
                ip_alerts = alerts_df[alerts_df["source_ip"] == lookup_ip]
                if not ip_alerts.empty:
                    st.subheader(f"📋 Alert history for {lookup_ip} ({len(ip_alerts)} alerts)")
                    show_cols = [c for c in
                        ["timestamp","attack_type","severity","risk_score",
                         "destination_ip","scan_type"]
                        if c in ip_alerts.columns]
                    st.dataframe(
                        ip_alerts[show_cols].style.apply(colour_row, axis=1),
                        use_container_width=True
                    )

                    # Connection attempts timeline for this IP
                    try:
                        ip_ts = ip_alerts.copy()
                        ip_ts["timestamp"] = pd.to_datetime(ip_ts["timestamp"])
                        ip_ts = ip_ts.set_index("timestamp").sort_index()
                        activity = (
                            ip_ts.resample("1min")["id"].count()
                            .reset_index()
                        )
                        activity.columns = ["time","alerts"]
                        st.subheader("📈 Attack timeline for this IP")
                        st.area_chart(activity.set_index("time")["alerts"])
                    except Exception:
                        pass
                else:
                    st.info(f"No alerts recorded for {lookup_ip} in local DB.")

            # Quick block button
            st.divider()
            if st.button(f"🚫 Block {lookup_ip} now", key=f"block_{lookup_ip}"):
                res = eng_post("/block_ip", {"ip": lookup_ip})
                if res.get("status") == "blocked":
                    st.success(f"Blocked {lookup_ip}")
                else:
                    st.error(res.get("msg", "Error — check if engine is running"))
        else:
            st.error(
                f"Could not retrieve intel for `{lookup_ip}`. "
                "Check your internet connection or try a valid public IP."
            )

    elif not lookup_ip:
        st.info(
            "Enter a public IP above or pick from the 'recent attackers' "
            "dropdown (populated when alerts exist)."
        )

# ── TAB 8: NOTIFICATIONS ─────────────────────────────────────────────────────

with t8:
    st.subheader("🔔 Alert Notifications")
    st.caption(
        "AegisNet can notify you instantly when a High severity alert fires. "
        "Configure your channels below — credentials are stored in your `.env` file, never hardcoded."
    )

    notify_email    = status.get("notify_email",    False) if status else False
    notify_telegram = status.get("notify_telegram", False) if status else False

    sc1, sc2 = st.columns(2)
    sc1.metric("Email Alerts",    "🟢 Enabled" if notify_email    else "⚫ Disabled")
    sc2.metric("Telegram Alerts", "🟢 Enabled" if notify_telegram else "⚫ Disabled")

    st.divider()

    with st.expander("📧 Email Setup (Gmail)", expanded=not notify_email):
        st.markdown("""
**Step-by-step:**
1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Create an App Password for "Mail" → copy the 16-character code
3. Add these lines to your `.env` file in the project folder:
```
NOTIFY_EMAIL=1
NOTIFY_EMAIL_FROM=your@gmail.com
NOTIFY_EMAIL_TO=your@gmail.com
NOTIFY_EMAIL_PASS=xxxx xxxx xxxx xxxx
```
4. Restart `realengine.py`
        """)

    with st.expander("✈️ Telegram Setup", expanded=not notify_telegram):
        st.markdown("""
**Step-by-step:**
1. Open Telegram → search **@BotFather** → send `/newbot` → copy the token
2. Open: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` to get your chat ID
3. Add to your `.env` file:
```
NOTIFY_TELEGRAM=1
NOTIFY_TELEGRAM_TOKEN=123456789:ABCdef...
NOTIFY_TELEGRAM_CHAT_ID=987654321
```
4. Restart `realengine.py`
        """)

    st.divider()
    st.subheader("🧪 Test Your Notifications")
    if st.button("📤 Send Test Notification", key="test_notify"):
        res = eng_post("/test_notify", {})
        if res.get("status") == "sent":
            st.success(f"✅ Test sent via: {', '.join(res.get('channels', []))}")
        elif res.get("status") == "no_channels":
            st.warning(res.get("msg", "No channels configured."))
        else:
            st.error("Engine unreachable.")

    st.divider()
    st.subheader("📋 Recent High Severity Events")
    if not alerts_df.empty:
        high_alerts = alerts_df[alerts_df["severity"] == "High"]
        if not high_alerts.empty:
            show_cols = [c for c in
                ["timestamp","source_ip","attack_type","risk_score","country","isp"]
                if c in high_alerts.columns]
            st.dataframe(high_alerts[show_cols].head(20), use_container_width=True)
        else:
            st.info("No High severity alerts yet.")
    else:
        st.info("No alerts yet.")

# ── TAB 9: ADMIN ─────────────────────────────────────────────────────────────

with t9:
    st.subheader("🛠️ Manual IP Control")
    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("**Block an IP**")
        ip_b = st.text_input("IP to block", key="blk")
        if st.button("🚫 Block"):
            if ip_b:
                res = eng_post("/block_ip", {"ip": ip_b})
                if res.get("status") == "blocked":
                    st.success(f"Blocked {ip_b}")
                else:
                    st.error(res.get("msg", "Error"))

    with col_r:
        st.markdown("**Unblock an IP**")
        ip_u = st.text_input("IP to unblock", key="ublk")
        if st.button("✅ Unblock"):
            if ip_u:
                res = eng_post("/unblock_ip", {"ip": ip_u})
                st.success(f"Unblocked {ip_u}") if res.get("status") == "unblocked" \
                    else st.error("Error")

    st.divider()
    st.subheader("🟢 IP Whitelist")
    st.caption("IPs on this list are never auto-blocked by the engine.")

    wl_data = eng("/whitelist")
    if isinstance(wl_data, list) and wl_data:
        wl_df = pd.DataFrame({"whitelisted_ip": wl_data})
        st.dataframe(wl_df, use_container_width=True)

    col_wa, col_wr = st.columns(2)
    with col_wa:
        wl_add = st.text_input("Add to whitelist", key="wla")
        if st.button("Add"):
            if wl_add:
                r = eng_post("/whitelist", {"ip": wl_add})
                st.success(f"Added {wl_add}") if r.get("status") == "added" \
                    else st.error("Error")
    with col_wr:
        wl_rm = st.text_input("Remove from whitelist", key="wlr")
        if st.button("Remove"):
            if wl_rm:
                try:
                    r = requests.delete(
                        f"{ENGINE}/whitelist", json={"ip": wl_rm}, timeout=3
                    ).json()
                    st.success(f"Removed {wl_rm}") if r.get("status") == "removed" \
                        else st.error("Error")
                except Exception:
                    st.error("Engine unreachable")

    st.divider()
    st.subheader("🚫 Blocked IPs Table")
    if blocked_df.empty:
        st.success("No IPs currently blocked.")
    else:
        st.dataframe(blocked_df, use_container_width=True)

    st.divider()
    st.subheader("🔧 Engine Status (raw)")
    if status:
        st.json(status)
    else:
        st.warning("Engine offline.")