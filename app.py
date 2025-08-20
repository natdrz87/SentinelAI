#!/usr/bin/env python3
"""
SentinelAI - Streamlit Web Interface
Web application for AI-powered cybersecurity log analysis
"""

import streamlit as st
import json
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
from main import SentinelAI

# Page configuration
st.set_page_config(
    page_title="SentinelAI - Cybersecurity Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #667eea;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .threat-alert {
        background: #fee;
        border: 1px solid #fcc;
        padding: 0.5rem;
        border-radius: 5px;
        color: #c53030;
        margin: 0.5rem 0;
    }
    
    .safe-alert {
        background: #efe;
        border: 1px solid #cfc;
        padding: 0.5rem;
        border-radius: 5px;
        color: #38a169;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize SentinelAI
@st.cache_resource
def init_sentinelai():
    return SentinelAI()

def main():
    """Main Streamlit application"""
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ SentinelAI - AI Cybersecurity Dashboard</h1>
        <p>Real-time threat detection and log analysis powered by AI</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize SentinelAI
    sentinel = init_sentinelai()
    
    # Sidebar
    st.sidebar.title("🔧 SentinelAI Controls")
    page = st.sidebar.selectbox(
        "Choose Analysis Type",
        ["🏠 Dashboard", "🔍 Log Analysis", "📊 Batch Analysis", "📈 Statistics", "ℹ️ About"]
    )
    
    # Dashboard Page
    if page == "🏠 Dashboard":
        show_dashboard(sentinel)
    
    # Log Analysis Page
    elif page == "🔍 Log Analysis":
        show_log_analysis(sentinel)
    
    # Batch Analysis Page
    elif page == "📊 Batch Analysis":
        show_batch_analysis(sentinel)
    
    # Statistics Page
    elif page == "📈 Statistics":
        show_statistics(sentinel)
    
    # About Page
    elif page == "ℹ️ About":
        show_about()

def show_dashboard(sentinel):
    """Display main dashboard"""
    st.header("🏠 Security Overview Dashboard")
    
    # Get statistics
    stats = sentinel.get_stats()
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🔍 Total Analyses",
            value=stats['total_analyses'],
            delta="+12 today"
        )
    
    with col2:
        st.metric(
            label="⚠️ Threats Detected",
            value=stats['threats_detected'],
            delta="+3 today",
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            label="✅ Safe Events",
            value=stats['safe_events'],
            delta="+9 today"
        )
    
    with col4:
        st.metric(
            label="🎯 Accuracy Rate",
            value=stats['accuracy_rate'],
            delta="+0.2%"
        )
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat distribution pie chart
        threat_data = pd.DataFrame({
            'Type': ['Safe Events', 'Suspicious', 'Critical'],
            'Count': [stats['safe_events'], max(1, stats['threats_detected'] - 2), 2]
        })
        
        fig_pie = px.pie(
            threat_data, 
            values='Count', 
            names='Type',
            title="🍰 Threat Distribution",
            color_discrete_map={
                'Safe Events': '#27ae60',
                'Suspicious': '#f39c12', 
                'Critical': '#e74c3c'
            }
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Time series chart (mock data)
        dates = pd.date_range(start=datetime.now() - timedelta(days=7), end=datetime.now(), freq='D')
        time_data = pd.DataFrame({
            'Date': dates,
            'Threats': [5, 8, 3, 12, 6, 9, 4],
            'Safe Events': [45, 52, 38, 48, 41, 47, 39]
        })
        
        fig_line = go.Figure()
        fig_line.add_trace(go.Scatter(
            x=time_data['Date'], 
            y=time_data['Threats'],
            mode='lines+markers',
            name='Threats',
            line=dict(color='#e74c3c')
        ))
        fig_line.add_trace(go.Scatter(
            x=time_data['Date'], 
            y=time_data['Safe Events'],
            mode='lines+markers',
            name='Safe Events',
            line=dict(color='#27ae60')
        ))
        fig_line.update_layout(title="📈 7-Day Trend Analysis")
        st.plotly_chart(fig_line, use_container_width=True)
    
    # Recent alerts section
    st.subheader("🚨 Recent Security Alerts")
    
    # Mock recent alerts
    alerts = [
        {"time": "2 minutes ago", "type": "Suspicious", "message": "Multiple failed SSH attempts detected"},
        {"time": "15 minutes ago", "type": "Safe", "message": "User authentication successful"},
        {"time": "1 hour ago", "type": "Critical", "message": "Malware signature detected in email"},
        {"time": "2 hours ago", "type": "Safe", "message": "System backup completed successfully"}
    ]
    
    for alert in alerts:
        if alert['type'] == 'Critical' or alert['type'] == 'Suspicious':
            st.markdown(f"""
            <div class="threat-alert">
                <strong>⚠️ {alert['type']}</strong> - {alert['time']}<br>
                {alert['message']}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="safe-alert">
                <strong>✅ {alert['type']}</strong> - {alert['time']}<br>
                {alert['message']}
            </div>
            """, unsafe_allow_html=True)

def show_log_analysis(sentinel):
    """Display log analysis interface"""
    st.header("🔍 Real-time Log Analysis")
    
    st.write("Enter a security log entry below for AI-powered analysis:")
    
    # Sample logs for quick testing
    sample_logs = {
        "SSH Brute Force": "Failed password for root from 185.220.101.42 port 33891 ssh2",
        "Web Attack": "GET /admin/config.php HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0 (compatible; N
