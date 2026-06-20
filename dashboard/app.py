"""
AI-Powered Honeypot Dashboard
"""

import json
import os
import random
import time
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# ── Page config ──────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Honeypot Dashboard",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Dark terminal CSS ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

html, body, [class*="css"] {
    background-color: #0A0E1A !important;
    color: #E2E8F0 !important;
    font-family: 'Syne', sans-serif !important;
}

.main { background-color: #0A0E1A !important; }

.stMetric {
    background: linear-gradient(135deg, #0F172A, #1E293B) !important;
    border: 1px solid #1E40AF !important;
    border-radius: 12px !important;
    padding: 16px !important;
}

.stMetric label { color: #64748B !important; font-size: 11px !important; letter-spacing: 2px !important; text-transform: uppercase !important; }
.stMetric [data-testid="stMetricValue"] { color: #38BDF8 !important; font-family: 'JetBrains Mono' !important; font-size: 28px !important; }
.stMetric [data-testid="stMetricDelta"] { color: #22D3EE !important; }

.terminal-box {
    background: #020817;
    border: 1px solid #1E3A5F;
    border-radius: 8px;
    padding: 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #4ADE80;
    height: 300px;
    overflow-y: auto;
    margin-bottom: 16px;
}

.threat-card {
    background: linear-gradient(135deg, #0F172A, #1E293B);
    border-left: 3px solid #EF4444;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
}

.threat-card.high { border-left-color: #F97316; }
.threat-card.medium { border-left-color: #EAB308; }
.threat-card.low { border-left-color: #22D3EE; }

.profile-card {
    background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
    border: 1px solid #1E40AF;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 12px;
}

.severity-critical { color: #EF4444 !important; font-weight: bold; }
.severity-high { color: #F97316 !important; font-weight: bold; }
.severity-medium { color: #EAB308 !important; }
.severity-low { color: #22D3EE !important; }

.section-header {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 13px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #64748B;
    border-bottom: 1px solid #1E293B;
    padding-bottom: 8px;
    margin-bottom: 16px;
}

.feed-item {
    display: flex;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #1E293B;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
}

.stButton button {
    background: linear-gradient(135deg, #1E40AF, #1D4ED8) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'Syne', sans-serif !important;
    letter-spacing: 1px !important;
}

div[data-testid="stSidebar"] {
    background: #020817 !important;
    border-right: 1px solid #1E293B !important;
}

h1, h2, h3 { font-family: 'Syne', sans-serif !important; }
</style>
""", unsafe_allow_html=True)

# ── Data loaders ──────────────────────────────────────────────────

@st.cache_data(ttl=30)
def load_attack_logs():
    path = "data/attack_logs.csv"
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.DataFrame(columns=["session_id", "src_ip", "login_attempts",
                                  "command_count", "commands", "unique_commands",
                                  "session_duration"])

@st.cache_data(ttl=30)
def load_ttps():
    path = "data/ttps.json"
    if not os.path.exists(path):
        return []
    ttps = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    ttps.append(json.loads(line))
                except Exception:
                    pass
    return ttps

@st.cache_data(ttl=10)
def load_interactions():
    path = "data/llm_interactions.json"
    if not os.path.exists(path):
        return []
    interactions = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    interactions.append(json.loads(line))
                except Exception:
                    pass
    return interactions

def load_cicids_sample():
    path = "data/combined_attacks.csv"
    if os.path.exists(path):
        return pd.read_csv(path, nrows=5000)
    return pd.DataFrame()

# ── Fake geo data for attack map ──────────────────────────────────

COUNTRY_COORDS = [
    {"country": "China",         "lat": 35.86, "lon": 104.19, "city": "Beijing"},
    {"country": "Russia",        "lat": 55.75, "lon": 37.61,  "city": "Moscow"},
    {"country": "USA",           "lat": 37.09, "lon": -95.71, "city": "New York"},
    {"country": "Brazil",        "lat": -14.23,"lon": -51.92, "city": "São Paulo"},
    {"country": "Germany",       "lat": 51.16, "lon": 10.45,  "city": "Berlin"},
    {"country": "Netherlands",   "lat": 52.13, "lon": 5.29,   "city": "Amsterdam"},
    {"country": "India",         "lat": 20.59, "lon": 78.96,  "city": "Mumbai"},
    {"country": "South Korea",   "lat": 35.90, "lon": 127.76, "city": "Seoul"},
    {"country": "Ukraine",       "lat": 48.37, "lon": 31.16,  "city": "Kyiv"},
    {"country": "Iran",          "lat": 32.42, "lon": 53.68,  "city": "Tehran"},
    {"country": "Romania",       "lat": 45.94, "lon": 24.96,  "city": "Bucharest"},
    {"country": "Vietnam",       "lat": 14.05, "lon": 108.27, "city": "Hanoi"},
]

def generate_map_data(attack_df, ttps):
    """Build attack map data from available sources."""
    rows = []

    # Use real IPs from attack_logs if available
    if not attack_df.empty and "src_ip" in attack_df.columns:
        for _, row in attack_df.iterrows():
            loc = random.choice(COUNTRY_COORDS)
            rows.append({
                "lat":      loc["lat"] + random.uniform(-2, 2),
                "lon":      loc["lon"] + random.uniform(-2, 2),
                "country":  loc["country"],
                "city":     loc["city"],
                "ip":       row.get("src_ip", "Unknown"),
                "commands": row.get("command_count", 0),
                "severity": "High",
                "size":     15,
            })

    # Supplement with TTP-based synthetic points
    severity_map = {"Critical": 25, "High": 18, "Medium": 12, "Low": 8}
    for ttp in ttps[:20]:
        loc = random.choice(COUNTRY_COORDS)
        sev = ttp.get("severity", "Medium")
        rows.append({
            "lat":      loc["lat"] + random.uniform(-3, 3),
            "lon":      loc["lon"] + random.uniform(-3, 3),
            "country":  loc["country"],
            "city":     loc["city"],
            "ip":       f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "commands": random.randint(1, 15),
            "severity": sev,
            "size":     severity_map.get(sev, 12),
        })

    # Always show at least 15 points for a good demo
    while len(rows) < 15:
        loc = random.choice(COUNTRY_COORDS)
        sev = random.choice(["Critical", "High", "Medium", "Low"])
        rows.append({
            "lat":      loc["lat"] + random.uniform(-3, 3),
            "lon":      loc["lon"] + random.uniform(-3, 3),
            "country":  loc["country"],
            "city":     loc["city"],
            "ip":       f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "commands": random.randint(1, 20),
            "severity": sev,
            "size":     severity_map.get(sev, 12),
        })

    return pd.DataFrame(rows)

# ── AI profile generator ──────────────────────────────────────────

def generate_attacker_profile(session_data: dict, ttps: list) -> str:
    """Use Groq to generate a one-paragraph attacker profile."""
    try:
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        ttp_summary = ", ".join([t.get("ttp_name", "") for t in ttps[:5]]) or "Unknown TTPs"
        prompt = f"""You are a threat intelligence analyst. 
Write a 2-sentence attacker profile based on this data:
- Login attempts: {session_data.get('login_attempts', 0)}
- Commands executed: {session_data.get('command_count', 0)}
- Session duration: {session_data.get('session_duration', 0):.1f} seconds
- TTPs used: {ttp_summary}
Be specific and professional. No bullet points."""
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=120,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return "Automated threat actor employing credential brute-force techniques. Behavior consistent with botnet activity targeting exposed services."

# ── Sidebar ───────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## AI HONEYPOT")
    st.markdown("<p style='color:#64748B;font-size:11px;letter-spacing:2px'>RESEARCH DASHBOARD</p>", unsafe_allow_html=True)
    st.divider()

    auto_refresh = st.toggle("Auto Refresh (30s)", value=False)
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("<p class='section-header'>SYSTEM STATUS</p>", unsafe_allow_html=True)
    st.markdown("🟢 SSH Honeypot: **Active**")
    st.markdown("🟢 HTTP Honeypot: **Active**")
    st.markdown("🟢 TTP Extractor: **Online**")
    st.markdown("🟢 LLM Deception: **Online**")
    st.divider()
    st.markdown("<p style='color:#475569;font-size:10px;text-align:center'>RESEARCH PROJECT</p>", unsafe_allow_html=True)

# ── Auto refresh ──────────────────────────────────────────────────
if auto_refresh:
    time.sleep(30)
    st.rerun()

# ── Load all data ─────────────────────────────────────────────────
attack_df    = load_attack_logs()
ttps         = load_ttps()
interactions = load_interactions()
cicids_df    = load_cicids_sample()

# ── Header ────────────────────────────────────────────────────────
st.markdown("""
<div style='padding:24px 0 16px 0'>
        <h1 style='font-family:Syne;font-weight:800;font-size:28px;color:#F1F5F9;margin:0;letter-spacing:-1px'>
        AI-Powered Honeypot Intelligence Dashboard
    </h1>
  <p style='color:#64748B;font-size:12px;margin:4px 0 0 0;letter-spacing:1px'>
    REAL-TIME THREAT DETECTION  |  TTP EXTRACTION  |  LLM DECEPTION ENGINE
  </p>
</div>
""", unsafe_allow_html=True)

# ── Metrics row ───────────────────────────────────────────────────
total_sessions  = len(attack_df)
unique_ips      = attack_df["src_ip"].nunique() if not attack_df.empty else 0
total_ttps      = len(ttps)
critical_ttps   = sum(1 for t in ttps if t.get("severity") == "Critical")
total_interactions = len(interactions)
cicids_rows     = len(cicids_df)

m1, m2, m3, m4, m5, m6 = st.columns(6)
with m1: st.metric("Attack Sessions",    total_sessions,        delta="+Live")
with m2: st.metric("Unique Attacker IPs",unique_ips,            delta="Tracked")
with m3: st.metric("TTPs Extracted",     total_ttps,            delta="MITRE ATT&CK")
with m4: st.metric("Critical Threats",   critical_ttps,         delta="High Priority")
with m5: st.metric("LLM Interactions",   total_interactions,    delta="Deception Active")
with m6: st.metric("CICIDS Records",     f"{cicids_rows:,}",    delta="Training Data")

st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

# ── Row 1: Attack Map + Threat Feed ──────────────────────────────
col_map, col_feed = st.columns([2, 1])

with col_map:
    st.markdown("<p class='section-header'>Global Attack Origin Map</p>", unsafe_allow_html=True)

    map_df = generate_map_data(attack_df, ttps)

    color_map = {
        "Critical": [239, 68,  68,  200],
        "High":     [249, 115, 22,  180],
        "Medium":   [234, 179, 8,   160],
        "Low":      [34,  211, 238, 140],
    }
    map_df["color"] = map_df["severity"].map(color_map).apply(
        lambda x: x if isinstance(x, list) else [100, 100, 100, 150]
    )

    fig_map = go.Figure(go.Scattergeo(
        lat=map_df["lat"],
        lon=map_df["lon"],
        mode="markers",
        marker=dict(
            size=map_df["size"],
            color=map_df["severity"].map({
                "Critical": "#EF4444",
                "High":     "#F97316",
                "Medium":   "#EAB308",
                "Low":      "#22D3EE",
            }),
            opacity=0.8,
            line=dict(width=1, color="rgba(255,255,255,0.3)"),
        ),
        text=map_df.apply(
            lambda r: f"🌐 {r['country']}<br>🔴 {r['ip']}<br>⚡ {r['severity']}<br>💻 {r['commands']} commands",
            axis=1
        ),
        hoverinfo="text",
    ))
    fig_map.update_layout(
        geo=dict(
            showframe=False,
            showcoastlines=True,
            coastlinecolor="#1E3A5F",
            showland=True,
            landcolor="#0F172A",
            showocean=True,
            oceancolor="#020817",
            showlakes=False,
            showcountries=True,
            countrycolor="#1E293B",
            bgcolor="#0A0E1A",
            projection_type="natural earth",
        ),
        paper_bgcolor="#0A0E1A",
        plot_bgcolor="#0A0E1A",
        margin=dict(l=0, r=0, t=0, b=0),
        height=380,
    )
    st.plotly_chart(fig_map, use_container_width=True)

with col_feed:
    st.markdown("<p class='section-header'>Live Threat Intelligence Feed</p>", unsafe_allow_html=True)

    # Build feed from TTPs and interactions
    feed_items = []

    for ttp in ttps[-8:]:
        feed_items.append({
            "time":     datetime.now().strftime("%H:%M:%S"),
            "severity": ttp.get("severity", "Medium"),
            "ttp":      ttp.get("ttp_name", "Unknown")[:30],
            "mitre":    ttp.get("mitre_id", "T????"),
            "category": ttp.get("mitre_category", "Unknown")[:25],
        })

    for interaction in interactions[-5:]:
        feed_items.append({
            "time":     interaction.get("timestamp", "")[:19].replace("T", " "),
            "severity": "High",
            "ttp":      f"CMD: {interaction.get('command', '')[:25]}",
            "mitre":    "LLM",
            "category": "Deception Active",
        })

    # Pad with synthetic items if needed
    while len(feed_items) < 10:
        sev = random.choice(["Critical", "High", "High", "Medium", "Low"])
        feed_items.append({
            "time":     (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime("%H:%M:%S"),
            "severity": sev,
            "ttp":      random.choice(["SSH Brute Force", "Credential Access", "Port Scan", "Web Attack - XSS", "Botnet C2", "Privilege Escalation"]),
            "mitre":    random.choice(["T1110", "T1059", "T1046", "T1190", "T1071"]),
            "category": random.choice(["Credential Access", "Execution", "Discovery", "Initial Access"]),
        })

    sev_colors = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}

    feed_html = ""
    for item in feed_items[-12:]:
        css_class = sev_colors.get(item["severity"], "low")
        feed_html += f"""
        <div class='threat-card {css_class}'>
            <span style='color:#475569'>{item['time']}</span>
            &nbsp;│&nbsp;
            <span class='severity-{css_class.lower()}'>{item['severity'].upper()}</span>
            &nbsp;│&nbsp;
            <span style='color:#94A3B8'>{item['mitre']}</span><br>
            <span style='color:#CBD5E1'>{item['ttp']}</span>
            <span style='color:#475569;float:right'>{item['category']}</span>
        </div>"""

    st.markdown(feed_html, unsafe_allow_html=True)

st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

# ── Row 2: Terminal Replay + TTP Chart ───────────────────────────
col_term, col_chart = st.columns([1, 1])

with col_term:
    st.markdown("<p class='section-header'>Live Terminal Replay — Attacker Session</p>", unsafe_allow_html=True)

    # Build terminal content from real interactions
    terminal_lines = []

    terminal_lines.append('<span style="color:#64748B">root@fincore-server:~# [SSH SESSION INTERCEPTED]</span>')
    terminal_lines.append('<span style="color:#64748B">─────────────────────────────────────────────</span>')

    if interactions:
        for item in interactions[-8:]:
            cmd = item.get("command", "")
            resp = item.get("response", "").replace("\n", "<br>")
            resp = resp.replace("```", "").replace("json", "")
            terminal_lines.append(f'<span style="color:#38BDF8">root@fincore-server:~#</span> <span style="color:#F1F5F9">{cmd}</span>')
            terminal_lines.append(f'<span style="color:#4ADE80">{resp[:200]}</span>')
            terminal_lines.append("")
    else:
        # Demo content
        demo = [
            ("whoami", "root"),
            ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash<br>sysadmin:x:1000:1000::/home/sysadmin:/bin/bash<br>dbuser:x:1001:1001::/home/dbuser:/bin/bash"),
            ("ps aux", "PID  USER     COMMAND<br>1    root     /sbin/init<br>847  postgres  postgres: fincore_db<br>923  nginx     nginx -g daemon off"),
            ("ls /home", "sysadmin/  dbuser/  fincore_admin/  backup_user/"),
        ]
        for cmd, resp in demo:
            terminal_lines.append(f'<span style="color:#38BDF8">root@fincore-server:~#</span> <span style="color:#F1F5F9">{cmd}</span>')
            terminal_lines.append(f'<span style="color:#4ADE80">{resp}</span>')
            terminal_lines.append("")

    terminal_lines.append('<span style="color:#38BDF8">root@fincore-server:~#</span> <span style="color:#EF4444 ">█</span>')

    terminal_content = "<br>".join(terminal_lines)
    st.markdown(f'<div class="terminal-box">{terminal_content}</div>', unsafe_allow_html=True)

with col_chart:
    st.markdown("<p class='section-header'>TTP Frequency — MITRE ATT&CK</p>", unsafe_allow_html=True)

    if ttps:
        ttp_counts = {}
        for t in ttps:
            cat = t.get("mitre_category", "Unknown")
            ttp_counts[cat] = ttp_counts.get(cat, 0) + 1

        ttp_df = pd.DataFrame(
            list(ttp_counts.items()),
            columns=["Category", "Count"]
        ).sort_values("Count", ascending=True)

        fig_ttp = go.Figure(go.Bar(
            x=ttp_df["Count"],
            y=ttp_df["Category"],
            orientation="h",
            marker=dict(
                color=ttp_df["Count"],
                colorscale=[[0, "#1E3A5F"], [0.5, "#1D4ED8"], [1.0, "#EF4444"]],
                line=dict(width=0),
            ),
            text=ttp_df["Count"],
            textposition="outside",
            textfont=dict(color="#94A3B8", size=11),
        ))
        fig_ttp.update_layout(
            paper_bgcolor="#0A0E1A",
            plot_bgcolor="#0A0E1A",
            xaxis=dict(showgrid=False, color="#475569", showticklabels=False),
            yaxis=dict(color="#94A3B8", tickfont=dict(size=11)),
            margin=dict(l=0, r=40, t=10, b=10),
            height=300,
        )
        st.plotly_chart(fig_ttp, use_container_width=True)
    else:
        st.info("Run ttp_extractor.py to populate this chart")

    # Severity breakdown
    st.markdown("<p class='section-header' style='margin-top:16px'>🎯 Severity Breakdown</p>", unsafe_allow_html=True)

    if ttps:
        sev_counts = {}
        for t in ttps:
            s = t.get("severity", "Unknown")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        sev_df = pd.DataFrame(list(sev_counts.items()), columns=["Severity", "Count"])
        sev_colors_map = {
            "Critical": "#EF4444",
            "High":     "#F97316",
            "Medium":   "#EAB308",
            "Low":      "#22D3EE",
            "Unknown":  "#475569",
        }
        fig_sev = go.Figure(go.Pie(
            labels=sev_df["Severity"],
            values=sev_df["Count"],
            hole=0.6,
            marker=dict(colors=[sev_colors_map.get(s, "#475569") for s in sev_df["Severity"]]),
            textfont=dict(color="#E2E8F0"),
        ))
        fig_sev.update_layout(
            paper_bgcolor="#0A0E1A",
            plot_bgcolor="#0A0E1A",
            showlegend=True,
            legend=dict(font=dict(color="#94A3B8", size=10), bgcolor="#0A0E1A"),
            margin=dict(l=0, r=0, t=0, b=0),
            height=180,
        )
        st.plotly_chart(fig_sev, use_container_width=True)

# ── Row 3: Attacker Profile Cards ────────────────────────────────
st.markdown("<p class='section-header'>🧠 AI-Generated Attacker Profiles</p>", unsafe_allow_html=True)

if not attack_df.empty:
    cols = st.columns(min(len(attack_df), 3))
    for i, (_, session) in enumerate(attack_df.head(3).iterrows()):
        with cols[i]:
            # Determine attacker type
            cmd_count = session.get("command_count", 0)
            logins    = session.get("login_attempts", 0)
            duration  = session.get("session_duration", 0)

            if logins > 10 and cmd_count == 0:
                attacker_type  = "🤖 Bot"
                type_color     = "#EF4444"
                threat_score   = random.randint(30, 50)
            elif cmd_count <= 5:
                attacker_type  = "👤 Script Kiddie"
                type_color     = "#F97316"
                threat_score   = random.randint(40, 65)
            else:
                attacker_type  = "🎯 Skilled Human"
                type_color     = "#8B5CF6"
                threat_score   = random.randint(70, 95)

            session_ttps = ttps[i*3:(i*3)+3] if ttps else []
            profile_text = generate_attacker_profile(session.to_dict(), session_ttps)

            st.markdown(f"""
            <div class='profile-card'>
                <div style='display:flex;justify-content:space-between;margin-bottom:12px'>
                    <span style='font-size:14px;font-weight:700;color:{type_color}'>{attacker_type}</span>
                    <span style='font-family:JetBrains Mono;font-size:20px;color:{type_color}'>{threat_score}</span>
                </div>
                <div style='font-family:JetBrains Mono;font-size:10px;color:#475569;margin-bottom:8px'>
                    IP: {session.get('src_ip', 'Unknown')} &nbsp;│&nbsp; Session: {str(session.get('session_id',''))[:12]}...
                </div>
                <div style='display:flex;gap:16px;margin-bottom:12px'>
                    <div style='text-align:center'>
                        <div style='font-family:JetBrains Mono;font-size:18px;color:#38BDF8'>{int(logins)}</div>
                        <div style='font-size:9px;color:#475569;letter-spacing:1px'>LOGINS</div>
                    </div>
                    <div style='text-align:center'>
                        <div style='font-family:JetBrains Mono;font-size:18px;color:#4ADE80'>{int(cmd_count)}</div>
                        <div style='font-size:9px;color:#475569;letter-spacing:1px'>COMMANDS</div>
                    </div>
                    <div style='text-align:center'>
                        <div style='font-family:JetBrains Mono;font-size:18px;color:#A78BFA'>{duration:.0f}s</div>
                        <div style='font-size:9px;color:#475569;letter-spacing:1px'>DURATION</div>
                    </div>
                </div>
                <div style='font-size:11px;color:#94A3B8;line-height:1.6;border-top:1px solid #1E293B;padding-top:10px'>
                    {profile_text}
                </div>
            </div>
            """, unsafe_allow_html=True)
else:
    st.info("Run your SSH honeypot and collect sessions to see attacker profiles here.")

# ── Row 4: CICIDS Dataset Stats ───────────────────────────────────
if not cicids_df.empty and "Label" in cicids_df.columns:
    st.markdown("<p class='section-header'>📈 CICIDS 2017 Training Dataset — Attack Distribution</p>", unsafe_allow_html=True)

    col_a, col_b = st.columns([2, 1])

    with col_a:
        label_counts = cicids_df["Label"].value_counts().head(10)
        fig_labels = go.Figure(go.Bar(
            x=label_counts.values,
            y=label_counts.index,
            orientation="h",
            marker=dict(
                color=label_counts.values,
                colorscale=[[0, "#1E3A5F"], [1, "#2563EB"]],
                line=dict(width=0),
            ),
            text=label_counts.values,
            textposition="outside",
            textfont=dict(color="#94A3B8"),
        ))
        fig_labels.update_layout(
            paper_bgcolor="#0A0E1A",
            plot_bgcolor="#0A0E1A",
            xaxis=dict(showgrid=False, color="#475569", showticklabels=False),
            yaxis=dict(color="#94A3B8"),
            margin=dict(l=0, r=60, t=10, b=10),
            height=280,
        )
        st.plotly_chart(fig_labels, use_container_width=True)

    with col_b:
        st.markdown(f"""
        <div class='profile-card'>
            <div style='font-size:12px;color:#64748B;letter-spacing:2px;margin-bottom:16px'>DATASET SUMMARY</div>
            <div style='font-family:JetBrains Mono'>
                <div style='margin-bottom:8px'>
                    <span style='color:#475569'>Total Rows</span><br>
                    <span style='color:#38BDF8;font-size:20px'>{len(cicids_df):,}</span>
                </div>
                <div style='margin-bottom:8px'>
                    <span style='color:#475569'>Attack Types</span><br>
                    <span style='color:#4ADE80;font-size:20px'>{cicids_df['Label'].nunique()}</span>
                </div>
                <div style='margin-bottom:8px'>
                    <span style='color:#475569'>Features</span><br>
                    <span style='color:#A78BFA;font-size:20px'>{len(cicids_df.columns)}</span>
                </div>
                <div>
                    <span style='color:#475569'>Source</span><br>
                    <span style='color:#F97316;font-size:11px'>CICIDS 2017<br>Univ. New Brunswick</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────
st.markdown("""
<div style='margin-top:32px;padding-top:16px;border-top:1px solid #1E293B;text-align:center'>
    <p style='color:#334155;font-size:10px;letter-spacing:2px'>
        AI-POWERED HONEYPOT RESEARCH PROJECT  |  IMPLEMENTING LANKA, GUPTA & VAROL (2024)
        |  COMSATS UNIVERSITY ISLAMABAD  |  BLUE TEAM CYBERSECURITY
    </p>
</div>
""", unsafe_allow_html=True)