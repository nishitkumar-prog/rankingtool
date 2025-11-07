import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import requests
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from io import StringIO
import time
import json
from urllib.parse import quote_plus

# Page configuration
st.set_page_config(
    page_title="SEO Rank Tracker",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Constants
SCRAPER_API_KEY = "614a33d52e88c3fd0b15d60520ad3d98"
ADMIN_EMAIL = "admin@herovired.com"
ADMIN_PASSWORD = "herovired_admin_2024"

# Database functions
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('rank_tracker.db', check_same_thread=False)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  is_admin INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Keywords table
    c.execute('''CREATE TABLE IF NOT EXISTS keywords
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  keyword TEXT NOT NULL,
                  target_url TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Rankings table
    c.execute('''CREATE TABLE IF NOT EXISTS rankings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  keyword_id INTEGER,
                  rank_position INTEGER,
                  url TEXT,
                  page_title TEXT,
                  features TEXT,
                  checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (keyword_id) REFERENCES keywords (id))''')
    
    # Insert default admin and user if they don't exist
    admin_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    user_hash = hashlib.sha256("herovired123".encode()).hexdigest()
    
    try:
        c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                 (ADMIN_EMAIL, admin_hash, 1))
        c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                 ("seo@herovired.com", user_hash, 0))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    
    conn.close()

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(email, password):
    """Verify user credentials"""
    conn = sqlite3.connect('rank_tracker.db')
    c = conn.cursor()
    password_hash = hash_password(password)
    c.execute("SELECT id, is_admin FROM users WHERE email = ? AND password_hash = ?",
             (email, password_hash))
    result = c.fetchone()
    conn.close()
    return result

def add_user(email, password, is_admin=0):
    """Add new user to database"""
    conn = sqlite3.connect('rank_tracker.db')
    c = conn.cursor()
    password_hash = hash_password(password)
    try:
        c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                 (email, password_hash, is_admin))
        conn.commit()
        conn.close()
        return True, "User added successfully!"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "User already exists!"

def get_all_users():
    """Get all users from database"""
    conn = sqlite3.connect('rank_tracker.db')
    df = pd.read_sql_query("SELECT id, email, is_admin, created_at FROM users", conn)
    conn.close()
    return df

def delete_user(user_id):
    """Delete user from database"""
    conn = sqlite3.connect('rank_tracker.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def add_keyword(user_id, keyword, target_url):
    """Add keyword to track"""
    conn = sqlite3.connect('rank_tracker.db')
    c = conn.cursor()
    c.execute("INSERT INTO keywords (user_id, keyword, target_url) VALUES (?, ?, ?)",
             (user_id, keyword, target_url))
    keyword_id = c.lastrowid
    conn.commit()
    conn.close()
    return keyword_id

def get_user_keywords(user_id):
    """Get all keywords for a user"""
    conn = sqlite3.connect('rank_tracker.db')
    df = pd.read_sql_query(
        "SELECT id, keyword, target_url, created_at FROM keywords WHERE user_id = ?",
        conn, params=(user_id,))
    conn.close()
    return df

def delete_keyword(keyword_id):
    """Delete keyword and its rankings"""
    conn = sqlite3.connect('rank_tracker.db')
    c = conn.cursor()
    c.execute("DELETE FROM rankings WHERE keyword_id = ?", (keyword_id,))
    c.execute("DELETE FROM keywords WHERE id = ?", (keyword_id,))
    conn.commit()
    conn.close()

def save_ranking(keyword_id, rank_position, url, page_title, features):
    """Save ranking data"""
    conn = sqlite3.connect('rank_tracker.db')
    c = conn.cursor()
    c.execute("""INSERT INTO rankings (keyword_id, rank_position, url, page_title, features)
                 VALUES (?, ?, ?, ?, ?)""",
             (keyword_id, rank_position, url, page_title, json.dumps(features)))
    conn.commit()
    conn.close()

def get_ranking_history(keyword_id, days=30):
    """Get ranking history for a keyword"""
    conn = sqlite3.connect('rank_tracker.db')
    query = """
        SELECT rank_position, url, page_title, features, checked_at
        FROM rankings
        WHERE keyword_id = ? AND checked_at >= datetime('now', '-' || ? || ' days')
        ORDER BY checked_at DESC
    """
    df = pd.read_sql_query(query, conn, params=(keyword_id, days))
    conn.close()
    return df

def scrape_google_rankings(keyword, target_url, scraper_api_key):
    """Scrape Google rankings using ScraperAPI"""
    search_url = f"https://www.google.com/search?q={quote_plus(keyword)}&num=100&gl=in&hl=en"
    
    api_url = f"http://api.scraperapi.com?api_key={scraper_api_key}&url={quote_plus(search_url)}"
    
    try:
        response = requests.get(api_url, timeout=60)
        response.raise_for_status()
        html_content = response.text
        
        # Parse results
        results = parse_google_results(html_content, target_url)
        return results
        
    except Exception as e:
        st.error(f"Error scraping Google: {str(e)}")
        return None

def parse_google_results(html_content, target_url):
    """Parse Google search results from HTML"""
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(html_content, 'html.parser')
    results = {
        'rank': None,
        'url': None,
        'title': None,
        'features': []
    }
    
    # Check for AI Overview
    ai_overview = soup.find('div', {'class': lambda x: x and 'ai-overview' in x.lower()}) if soup.find('div', {'class': lambda x: x and 'ai-overview' in x.lower()}) else None
    if ai_overview:
        results['features'].append('AI Overview')
    
    # Check for People Also Ask
    paa = soup.find_all('div', {'class': lambda x: x and 'related-question' in str(x).lower()})
    if paa and len(paa) > 0:
        results['features'].append('People Also Ask')
    
    # Check for Featured Snippet
    featured_snippet = soup.find('div', {'class': lambda x: x and 'featured-snippet' in str(x).lower()})
    if featured_snippet:
        results['features'].append('Featured Snippet')
    
    # Find organic results
    organic_results = soup.find_all('div', {'class': 'g'})
    rank_counter = 1
    
    for result in organic_results:
        link_tag = result.find('a')
        if link_tag and 'href' in link_tag.attrs:
            url = link_tag['href']
            
            # Get title
            title_tag = result.find('h3')
            title = title_tag.get_text() if title_tag else "No title"
            
            # Check if this is our target URL
            if target_url.lower() in url.lower() and results['rank'] is None:
                results['rank'] = rank_counter
                results['url'] = url
                results['title'] = title
            
            rank_counter += 1
            
            if rank_counter > 100:
                break
    
    # If not found in top 100
    if results['rank'] is None:
        results['rank'] = 101  # Not in top 100
        results['url'] = target_url
        results['title'] = "Not found in top 100"
    
    return results

# Styling
def local_css():
    st.markdown("""
    <style>
        .main-header {
            font-size: 2.5rem;
            font-weight: bold;
            color: #1f77b4;
            text-align: center;
            margin-bottom: 2rem;
        }
        .metric-card {
            background-color: #f0f2f6;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stButton>button {
            width: 100%;
            border-radius: 5px;
            height: 3rem;
            font-weight: bold;
        }
        .feature-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            margin: 0.25rem;
            border-radius: 15px;
            background-color: #4CAF50;
            color: white;
            font-size: 0.85rem;
        }
    </style>
    """, unsafe_allow_html=True)

# Authentication
def login_page():
    """Login page"""
    st.markdown('<h1 class="main-header">🔐 SEO Rank Tracker Login</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### Sign In")
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login", type="primary"):
            if email and password:
                result = verify_user(email, password)
                if result:
                    st.session_state.logged_in = True
                    st.session_state.user_id = result[0]
                    st.session_state.user_email = email
                    st.session_state.is_admin = result[1]
                    st.rerun()
                else:
                    st.error("Invalid credentials!")
            else:
                st.warning("Please enter both email and password!")

# Admin Panel
def admin_panel():
    """Admin panel for user management"""
    st.markdown('<h1 class="main-header">👑 Admin Panel</h1>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["👥 Manage Users", "➕ Add User"])
    
    with tab1:
        st.subheader("All Users")
        users_df = get_all_users()
        users_df['is_admin'] = users_df['is_admin'].map({0: '❌', 1: '✅'})
        st.dataframe(users_df, use_container_width=True)
        
        st.subheader("Delete User")
        delete_email = st.selectbox("Select user to delete", 
                                    users_df[users_df['email'] != ADMIN_EMAIL]['email'].tolist())
        if st.button("🗑️ Delete User", type="secondary"):
            user_id = users_df[users_df['email'] == delete_email]['id'].values[0]
            delete_user(user_id)
            st.success(f"User {delete_email} deleted successfully!")
            st.rerun()
    
    with tab2:
        st.subheader("Add New User")
        new_email = st.text_input("Email")
        new_password = st.text_input("Password", type="password")
        is_admin = st.checkbox("Admin privileges")
        
        if st.button("Add User", type="primary"):
            if new_email and new_password:
                success, message = add_user(new_email, new_password, int(is_admin))
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.warning("Please fill all fields!")

# Main App
def main_app():
    """Main application"""
    st.markdown('<h1 class="main-header">📈 SEO Rank Tracker</h1>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👤 {st.session_state.user_email}")
        if st.session_state.is_admin:
            st.markdown("**🔑 Admin**")
        
        if st.button("🚪 Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Admin section
    if st.session_state.is_admin:
        if st.sidebar.button("👑 Admin Panel"):
            st.session_state.show_admin = True
        
        if st.session_state.get('show_admin', False):
            admin_panel()
            if st.button("← Back to Dashboard"):
                st.session_state.show_admin = False
                st.rerun()
            return
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "➕ Add Keywords", "🔍 Check Rankings"])
    
    with tab1:
        dashboard_view()
    
    with tab2:
        add_keywords_view()
    
    with tab3:
        check_rankings_view()

def dashboard_view():
    """Dashboard view with keyword list and rankings"""
    st.subheader("Your Keywords")
    
    keywords_df = get_user_keywords(st.session_state.user_id)
    
    if keywords_df.empty:
        st.info("No keywords added yet. Go to 'Add Keywords' tab to get started!")
        return
    
    # Display keywords with actions
    for idx, row in keywords_df.iterrows():
        with st.expander(f"🔑 {row['keyword']} | 🎯 {row['target_url']}", expanded=False):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                # Get ranking history
                history_df = get_ranking_history(row['id'], days=30)
                
                if not history_df.empty:
                    # Latest rank
                    latest_rank = history_df.iloc[0]['rank_position']
                    rank_color = "🟢" if latest_rank <= 10 else "🟡" if latest_rank <= 50 else "🔴"
                    st.metric("Current Rank", f"{rank_color} #{latest_rank}")
                    
                    # Features
                    if history_df.iloc[0]['features'] and history_df.iloc[0]['features'] != '[]':
                        features = json.loads(history_df.iloc[0]['features'])
                        st.markdown("**SERP Features:**")
                        for feature in features:
                            st.markdown(f'<span class="feature-badge">{feature}</span>', 
                                      unsafe_allow_html=True)
                    
                    # Ranking trend chart
                    if len(history_df) > 1:
                        st.markdown("**Ranking Trend (Last 30 Days)**")
                        history_df['checked_at'] = pd.to_datetime(history_df['checked_at'])
                        
                        fig = go.Figure()
                        fig.add_trace(go.Scatter(
                            x=history_df['checked_at'],
                            y=history_df['rank_position'],
                            mode='lines+markers',
                            name='Rank',
                            line=dict(color='#1f77b4', width=3),
                            marker=dict(size=8)
                        ))
                        
                        fig.update_layout(
                            yaxis=dict(autorange='reversed', title='Rank Position'),
                            xaxis=dict(title='Date'),
                            height=300,
                            margin=dict(l=20, r=20, t=20, b=20)
                        )
                        
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No ranking data yet. Check rankings in the 'Check Rankings' tab.")
            
            with col2:
                if st.button("🗑️ Delete", key=f"delete_{row['id']}"):
                    delete_keyword(row['id'])
                    st.success("Keyword deleted!")
                    st.rerun()

def add_keywords_view():
    """Add keywords view"""
    st.subheader("Add Keywords to Track")
    
    input_method = st.radio("Input Method", ["Manual Entry", "CSV Upload", "Paste from Clipboard"])
    
    if input_method == "Manual Entry":
        col1, col2 = st.columns(2)
        with col1:
            keyword = st.text_input("Keyword")
        with col2:
            target_url = st.text_input("Target URL (your website)")
        
        if st.button("Add Keyword", type="primary"):
            if keyword and target_url:
                add_keyword(st.session_state.user_id, keyword, target_url)
                st.success(f"Keyword '{keyword}' added successfully!")
                st.rerun()
            else:
                st.warning("Please fill all fields!")
    
    elif input_method == "CSV Upload":
        st.info("Upload a CSV file with columns: 'keyword' and 'target_url'")
        uploaded_file = st.file_uploader("Choose CSV file", type=['csv'])
        
        if uploaded_file:
            df = pd.read_csv(uploaded_file)
            if 'keyword' in df.columns and 'target_url' in df.columns:
                st.dataframe(df)
                if st.button("Import Keywords", type="primary"):
                    for _, row in df.iterrows():
                        add_keyword(st.session_state.user_id, row['keyword'], row['target_url'])
                    st.success(f"Imported {len(df)} keywords successfully!")
                    st.rerun()
            else:
                st.error("CSV must have 'keyword' and 'target_url' columns!")
    
    else:  # Paste from Clipboard
        st.info("Paste keywords (one per line) in format: keyword | target_url")
        text_input = st.text_area("Paste here", height=200)
        
        if st.button("Import Keywords", type="primary"):
            lines = text_input.strip().split('\n')
            count = 0
            for line in lines:
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) == 2:
                        keyword = parts[0].strip()
                        target_url = parts[1].strip()
                        add_keyword(st.session_state.user_id, keyword, target_url)
                        count += 1
            st.success(f"Imported {count} keywords successfully!")
            st.rerun()

def check_rankings_view():
    """Check rankings view"""
    st.subheader("Check Keyword Rankings")
    
    keywords_df = get_user_keywords(st.session_state.user_id)
    
    if keywords_df.empty:
        st.info("No keywords to check. Add some keywords first!")
        return
    
    # Select keywords to check
    selected_keywords = st.multiselect(
        "Select keywords to check",
        options=keywords_df['keyword'].tolist(),
        default=keywords_df['keyword'].tolist()[:5]
    )
    
    if st.button("🔍 Check Rankings Now", type="primary"):
        if not selected_keywords:
            st.warning("Please select at least one keyword!")
            return
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, keyword in enumerate(selected_keywords):
            status_text.text(f"Checking: {keyword}...")
            
            # Get keyword details
            keyword_row = keywords_df[keywords_df['keyword'] == keyword].iloc[0]
            keyword_id = keyword_row['id']
            target_url = keyword_row['target_url']
            
            # Scrape rankings
            results = scrape_google_rankings(keyword, target_url, SCRAPER_API_KEY)
            
            if results:
                save_ranking(
                    keyword_id,
                    results['rank'],
                    results['url'],
                    results['title'],
                    results['features']
                )
                
                # Display result
                rank_emoji = "🟢" if results['rank'] <= 10 else "🟡" if results['rank'] <= 50 else "🔴"
                st.success(f"{rank_emoji} {keyword}: Rank #{results['rank']}")
                
                if results['features']:
                    st.markdown(f"**Features:** {', '.join(results['features'])}")
            else:
                st.error(f"Failed to check: {keyword}")
            
            progress_bar.progress((i + 1) / len(selected_keywords))
            time.sleep(2)  # Rate limiting
        
        status_text.text("✅ All rankings checked!")
        st.balloons()

# Main execution
def main():
    """Main function"""
    init_db()
    local_css()
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if not st.session_state.logged_in:
        login_page()
    else:
        main_app()

if __name__ == "__main__":
    main()
