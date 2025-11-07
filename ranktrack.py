# streamlit_rank_tracker_complete.py
import os
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import requests
from datetime import datetime, timedelta
import plotly.graph_objects as go
from io import StringIO
import time
import json
from urllib.parse import quote_plus, urlparse, parse_qs
from typing import Optional

# -------------------------
# App configuration
# -------------------------
st.set_page_config(
    page_title="SEO Rank Tracker",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Read Scraper API key from Streamlit secrets or environment (do not hardcode keys here)
SCRAPER_API_KEY = (
    os.environ.get("SCRAPER_API_KEY")
    or (st.secrets.get("SCRAPER_API_KEY") if hasattr(st, "secrets") else None)
    or ""
)

DB_PATH = "rank_tracker.db"

# Default credentials for easy testing (CHANGE these in production)
# Login uses 'email' field; for convenience we create two default users:
# Admin credentials: email = "admin", password = "admin"
# Non-admin credentials: email = "user", password = "user"
DEFAULT_ADMIN_EMAIL = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
DEFAULT_USER_EMAIL = "user"
DEFAULT_USER_PASSWORD = "user"

# -------------------------
# Database helpers
# -------------------------
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    """Initialize SQLite DB and default users (only if missing)."""
    with get_conn() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      email TEXT UNIQUE NOT NULL,
                      password_hash TEXT NOT NULL,
                      is_admin INTEGER DEFAULT 0,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS keywords
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      keyword TEXT NOT NULL,
                      target_url TEXT NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users (id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS rankings
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      keyword_id INTEGER,
                      rank_position INTEGER,
                      url TEXT,
                      page_title TEXT,
                      features TEXT,
                      checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (keyword_id) REFERENCES keywords (id))''')
        # Insert default admin and user if not exist
        admin_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        user_hash = hash_password(DEFAULT_USER_PASSWORD)
        c.execute("SELECT id FROM users WHERE email = ?", (DEFAULT_ADMIN_EMAIL,))
        if not c.fetchone():
            c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                      (DEFAULT_ADMIN_EMAIL, admin_hash, 1))
        c.execute("SELECT id FROM users WHERE email = ?", (DEFAULT_USER_EMAIL,))
        if not c.fetchone():
            c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                      (DEFAULT_USER_EMAIL, user_hash, 0))
        conn.commit()

def hash_password(password: str) -> str:
    """Simple SHA256 hashing (ok for demo; use bcrypt in production)."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(email: str, password: str):
    """Return (id, is_admin) if credentials valid else None."""
    password_hash = hash_password(password)
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, is_admin FROM users WHERE email = ? AND password_hash = ?",
                  (email, password_hash))
        return c.fetchone()

def add_user(email: str, password: str, is_admin: int = 0):
    password_hash = hash_password(password)
    try:
        with get_conn() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                      (email, password_hash, is_admin))
            conn.commit()
        return True, "User added successfully!"
    except sqlite3.IntegrityError:
        return False, "User already exists!"

def get_all_users():
    with get_conn() as conn:
        return pd.read_sql_query("SELECT id, email, is_admin, created_at FROM users", conn)

def delete_user(user_id: int):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

def add_keyword(user_id: int, keyword: str, target_url: str) -> int:
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO keywords (user_id, keyword, target_url) VALUES (?, ?, ?)",
                  (user_id, keyword, target_url))
        conn.commit()
        return c.lastrowid

def get_user_keywords(user_id: int):
    with get_conn() as conn:
        return pd.read_sql_query(
            "SELECT id, keyword, target_url, created_at FROM keywords WHERE user_id = ?",
            conn, params=(user_id,)
        )

def delete_keyword(keyword_id: int):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM rankings WHERE keyword_id = ?", (keyword_id,))
        c.execute("DELETE FROM keywords WHERE id = ?", (keyword_id,))
        conn.commit()

def save_ranking(keyword_id: int, rank_position: int, url: str, page_title: str, features):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO rankings (keyword_id, rank_position, url, page_title, features)
                     VALUES (?, ?, ?, ?, ?)""",
                  (keyword_id, rank_position, url, page_title, json.dumps(features)))
        conn.commit()

def get_ranking_history(keyword_id: int, days: int = 30):
    with get_conn() as conn:
        query = """
            SELECT rank_position, url, page_title, features, checked_at
            FROM rankings
            WHERE keyword_id = ? AND checked_at >= datetime('now', '-' || ? || ' days')
            ORDER BY checked_at DESC
        """
        return pd.read_sql_query(query, conn, params=(keyword_id, days))

# -------------------------
# Scraping & parsing
# -------------------------
def extract_final_url(raw_url: str) -> str:
    """Handle Google's /url?q= redirect format."""
    if raw_url.startswith("/url?") or raw_url.startswith("/url?q=") or "/url?q=" in raw_url:
        parsed = urlparse(raw_url)
        q = parse_qs(parsed.query).get("q")
        if q:
            return q[0]
    return raw_url

def parse_google_results(html_content: str, target_url: str):
    """Robust-ish parsing of Google SERP HTML (best-effort)."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_content, 'html.parser')
    results = {"rank": None, "url": None, "title": None, "features": []}

    # SERP features (heuristics)
    if soup.find(lambda tag: tag.name == "div" and "ai-overview" in str(tag.get("class", "")).lower()):
        results["features"].append("AI Overview")
    if soup.find_all(lambda tag: tag.name == "div" and "related-question" in str(tag.get("class", "")).lower()):
        results["features"].append("People Also Ask")
    if soup.find(lambda tag: tag.name == "div" and ("featured" in str(tag.get("class", "")).lower() or "answer" in str(tag.get("class", "")).lower())):
        results["features"].append("Featured Snippet")

    # Find organic results by <a> > <h3> pattern
    h3_links = soup.select("a > h3")
    rank_counter = 1
    for h3 in h3_links:
        a_tag = h3.find_parent("a", href=True)
        if not a_tag:
            continue
        raw_href = a_tag["href"]
        final_url = extract_final_url(raw_href)
        title = h3.get_text(strip=True) or "No title"
        if target_url and target_url.lower().rstrip("/") in final_url.lower().rstrip("/") and results["rank"] is None:
            results["rank"] = rank_counter
            results["url"] = final_url
            results["title"] = title
        rank_counter += 1
        if rank_counter > 100:
            break

    # Fallback to div.g if nothing found
    if results["rank"] is None and not h3_links:
        organic = soup.select("div.g")
        rank_counter = 1
        for g in organic:
            a = g.find("a", href=True)
            h3 = g.find("h3")
            if not a or not h3:
                continue
            final_url = extract_final_url(a["href"])
            title = h3.get_text(strip=True) if h3 else "No title"
            if target_url and target_url.lower().rstrip("/") in final_url.lower().rstrip("/") and results["rank"] is None:
                results["rank"] = rank_counter
                results["url"] = final_url
                results["title"] = title
            rank_counter += 1
            if rank_counter > 100:
                break

    if results["rank"] is None:
        results["rank"] = 101
        results["url"] = target_url
        results["title"] = "Not found in top 100"

    return results

def scrape_google_rankings(keyword: str, target_url: str, scraper_api_key: Optional[str]):
    """
    Query ScraperAPI (or similar) and parse Google results.
    scraper_api_key can be set in Streamlit secrets or environment.
    """
    if not scraper_api_key:
        st.error("No Scraper API key configured. Set SCRAPER_API_KEY in Streamlit secrets or env vars.")
        return None

    search_url = f"https://www.google.com/search?q={quote_plus(keyword)}&num=100&gl=in&hl=en"
    api_url = f"https://api.scraperapi.com?api_key={scraper_api_key}&url={quote_plus(search_url)}&render=true"

    tries = 0
    max_tries = 2
    backoff = 1.5
    while tries <= max_tries:
        try:
            resp = requests.get(api_url, timeout=60)
            if resp.status_code >= 500:
                st.warning(f"Scraper provider returned HTTP {resp.status_code}. Attempt {tries+1}/{max_tries+1}")
                tries += 1
                time.sleep(backoff)
                backoff *= 2
                continue
            resp.raise_for_status()
            html_content = resp.text
            if not html_content or len(html_content) < 100:
                st.warning("Received unexpectedly small HTML response from scraper provider.")
                return None
            return parse_google_results(html_content, target_url)
        except requests.exceptions.HTTPError as he:
            st.error(f"HTTP error contacting scraper provider: {he}")
            return None
        except requests.exceptions.RequestException as e:
            st.warning(f"Network error contacting scraper provider: {e}. Attempt {tries+1}/{max_tries+1}")
            tries += 1
            time.sleep(backoff)
            backoff *= 2
            continue
    st.error("Failed to fetch results from ScraperAPI after multiple attempts.")
    return None

# -------------------------
# UI styling
# -------------------------
def local_css():
    st.markdown("""
    <style>
      .main-header { font-size: 2.2rem; font-weight:700; color:#1f77b4; text-align:center; margin-bottom:1rem; }
      .feature-badge { display:inline-block; padding:0.25rem 0.6rem; margin:0.25rem; border-radius:12px; background:#4CAF50; color:#fff; font-size:0.85rem; }
    </style>
    """, unsafe_allow_html=True)

# -------------------------
# Authentication UI
# -------------------------
def login_page():
    st.markdown('<h1 class="main-header">🔐 SEO Rank Tracker Login</h1>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("### Sign In")
        email = st.text_input("Email / Username", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login", type="primary"):
            if not email or not password:
                st.warning("Please enter both email and password!")
                return
            result = verify_user(email, password)
            if result:
                st.session_state.logged_in = True
                st.session_state.user_id = int(result[0])
                st.session_state.user_email = email
                st.session_state.is_admin = bool(result[1])
                # No explicit rerun here — returning is safer
                return
            else:
                st.error("Invalid credentials!")

# -------------------------
# Admin panel
# -------------------------
def admin_panel():
    st.markdown('<h1 class="main-header">👑 Admin Panel</h1>', unsafe_allow_html=True)
    tab1, tab2 = st.tabs(["👥 Manage Users", "➕ Add User"])
    with tab1:
        st.subheader("All Users")
        users_df = get_all_users()
        if users_df.empty:
            st.info("No users found.")
        else:
            users_df['is_admin'] = users_df['is_admin'].map({0: '❌', 1: '✅'})
            st.dataframe(users_df, use_container_width=True)
            st.subheader("Delete User")
            candidates = users_df[users_df['email'] != DEFAULT_ADMIN_EMAIL]['email'].tolist()
            if candidates:
                delete_email = st.selectbox("Select user to delete", candidates)
                if st.button("🗑️ Delete User", type="secondary"):
                    user_id = int(users_df[users_df['email'] == delete_email]['id'].values[0])
                    delete_user(user_id)
                    st.success(f"User {delete_email} deleted successfully!")
                    return
            else:
                st.info("No deletable users found.")
    with tab2:
        st.subheader("Add New User")
        new_email = st.text_input("Email", key="new_user_email")
        new_password = st.text_input("Password", type="password", key="new_user_password")
        is_admin = st.checkbox("Admin privileges", key="new_user_admin")
        if st.button("Add User", type="primary"):
            if new_email and new_password:
                success, message = add_user(new_email, new_password, int(is_admin))
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.warning("Please fill all fields!")

# -------------------------
# Main app views
# -------------------------
def dashboard_view():
    st.subheader("Your Keywords")
    keywords_df = get_user_keywords(st.session_state.user_id)
    if keywords_df.empty:
        st.info("No keywords added yet. Go to 'Add Keywords' tab to get started!")
        return
    for _, row in keywords_df.iterrows():
        with st.expander(f"🔑 {row['keyword']} | 🎯 {row['target_url']}", expanded=False):
            col1, col2 = st.columns([3, 1])
            with col1:
                history_df = get_ranking_history(row['id'], days=30)
                if not history_df.empty:
                    latest_row = history_df.iloc[0]
                    latest_rank = int(latest_row['rank_position'])
                    rank_color = "🟢" if latest_rank <= 10 else "🟡" if latest_rank <= 50 else "🔴"
                    st.metric("Current Rank", f"{rank_color} #{latest_rank}")
                    # features
                    try:
                        features = json.loads(latest_row['features']) if latest_row['features'] else []
                    except Exception:
                        features = []
                    if features:
                        st.markdown("**SERP Features:**")
                        for f in features:
                            st.markdown(f'<span class="feature-badge">{f}</span>', unsafe_allow_html=True)
                    # trend chart
                    if len(history_df) > 1:
                        history_df['checked_at'] = pd.to_datetime(history_df['checked_at'])
                        fig = go.Figure()
                        fig.add_trace(go.Scatter(
                            x=history_df['checked_at'],
                            y=history_df['rank_position'],
                            mode='lines+markers',
                            name='Rank'
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
                    return

def add_keywords_view():
    st.subheader("Add Keywords to Track")
    input_method = st.radio("Input Method", ["Manual Entry", "CSV Upload", "Paste from Clipboard"])
    if input_method == "Manual Entry":
        col1, col2 = st.columns(2)
        with col1:
            keyword = st.text_input("Keyword", key="manual_keyword")
        with col2:
            target_url = st.text_input("Target URL (your website)", key="manual_target")
        if st.button("Add Keyword", type="primary"):
            if keyword and target_url:
                add_keyword(st.session_state.user_id, keyword, target_url)
                st.success(f"Keyword '{keyword}' added successfully!")
                return
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
                    for _, r in df.iterrows():
                        add_keyword(st.session_state.user_id, r['keyword'], r['target_url'])
                    st.success(f"Imported {len(df)} keywords successfully!")
                    return
            else:
                st.error("CSV must have 'keyword' and 'target_url' columns!")
    else:
        st.info("Paste keywords (one per line) in format: keyword | target_url")
        text_input = st.text_area("Paste here", height=200, key="paste_keywords")
        if st.button("Import Keywords", type="primary"):
            lines = [ln.strip() for ln in text_input.strip().splitlines() if ln.strip()]
            count = 0
            for line in lines:
                if '|' in line:
                    parts = [p.strip() for p in line.split('|', 1)]
                    if len(parts) == 2:
                        add_keyword(st.session_state.user_id, parts[0], parts[1])
                        count += 1
            st.success(f"Imported {count} keywords successfully!")
            return

def check_rankings_view():
    st.subheader("Check Keyword Rankings")
    keywords_df = get_user_keywords(st.session_state.user_id)
    if keywords_df.empty:
        st.info("No keywords to check. Add some keywords first!")
        return
    selected_keywords = st.multiselect(
        "Select keywords to check",
        options=keywords_df['keyword'].tolist(),
        default=keywords_df['keyword'].tolist()[:5]
    )
    if st.button("🔍 Check Rankings Now", type="primary"):
        if not selected_keywords:
            st.warning("Please select at least one keyword!")
            return
        progress = st.progress(0)
        status = st.empty()
        total = len(selected_keywords)
        for i, keyword in enumerate(selected_keywords):
            status.text(f"Checking: {keyword} ({i+1}/{total})")
            keyword_row = keywords_df[keywords_df['keyword'] == keyword].iloc[0]
            keyword_id = int(keyword_row['id'])
            target_url = keyword_row['target_url']
            results = scrape_google_rankings(keyword, target_url, SCRAPER_API_KEY)
            if results:
                save_ranking(
                    keyword_id,
                    int(results['rank']),
                    results['url'],
                    results['title'],
                    results['features']
                )
                rank_emoji = "🟢" if results['rank'] <= 10 else "🟡" if results['rank'] <= 50 else "🔴"
                st.success(f"{rank_emoji} {keyword}: Rank #{results['rank']}")
                if results['features']:
                    st.markdown(f"**Features:** {', '.join(results['features'])}")
            else:
                st.error(f"Failed to check: {keyword} — see messages above for details.")
            progress.progress((i + 1) / total)
            time.sleep(0.6)
        status.text("✅ All rankings checked!")
        st.balloons()

# -------------------------
# Main entry
# -------------------------
def main():
    init_db()
    local_css()
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👤 {st.session_state.user_email}")
        if st.session_state.is_admin:
            st.markdown("**🔑 Admin**")
        if st.button("🚪 Logout"):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            return
        st.markdown("---")
        st.markdown("**App Settings**")
        scr_status = "configured" if SCRAPER_API_KEY else "NOT configured"
        st.write(f"Scraper API: {scr_status}")

    # Admin toggle
    if st.session_state.get('is_admin', False):
        if st.sidebar.button("👑 Admin Panel"):
            st.session_state.show_admin = True
        if st.session_state.get('show_admin', False):
            admin_panel()
            if st.button("← Back to Dashboard"):
                st.session_state.show_admin = False
            return

    st.markdown('<h1 class="main-header">📈 SEO Rank Tracker</h1>', unsafe_allow_html=True)
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "➕ Add Keywords", "🔍 Check Rankings"])
    with tab1:
        dashboard_view()
    with tab2:
        add_keywords_view()
    with tab3:
        check_rankings_view()

if __name__ == "__main__":
    main()
