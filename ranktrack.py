import os
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urlparse, parse_qs
import json
import time
import random
from datetime import datetime

# ------------------------
# CONFIG
# ------------------------
st.set_page_config(page_title="SEO Rank Tracker", page_icon="Chart", layout="wide")
SCRAPER_API_KEY = "614a33d52e88c3fd0b15d60520ad3d98"  # Your ScraperAPI key
DB_PATH = "rank_tracker.db"
DEFAULT_ADMIN_EMAIL = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
DEFAULT_USER_EMAIL = "user"
DEFAULT_USER_PASSWORD = "user"

# ------------------------
# DATABASE FUNCTIONS
# ------------------------
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    with get_conn() as conn:
        c = conn.cursor()

        # === USERS TABLE ===
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # === KEYWORDS TABLE (BASE) ===
        c.execute("""
        CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            keyword TEXT NOT NULL,
            target_url TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # === UPGRADE: Add target_domain if missing ===
        c.execute("PRAGMA table_info(keywords)")
        columns = [col[1] for col in c.fetchall()]
        if 'target_domain' not in columns:
            st.warning("Database upgrade: adding 'target_domain' column...")
            c.execute("ALTER TABLE keywords ADD COLUMN target_domain TEXT")

        # === BACKFILL target_domain for old rows ===
        c.execute("SELECT id, target_url FROM keywords WHERE target_domain IS NULL OR target_domain = ''")
        for kid, turl in c.fetchall():
            domain = urlparse(turl).netloc.replace("www.", "").lower()
            c.execute("UPDATE keywords SET target_domain = ? WHERE id = ?", (domain, kid))

        # === RANKINGS TABLE ===
        c.execute("""
        CREATE TABLE IF NOT EXISTS rankings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword_id INTEGER,
            rank_position INTEGER,
            url TEXT,
            page_title TEXT,
            features TEXT,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # === DEFAULT USERS ===
        admin_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        user_hash = hash_password(DEFAULT_USER_PASSWORD)

        c.execute("SELECT 1 FROM users WHERE email=?", (DEFAULT_ADMIN_EMAIL,))
        if not c.fetchone():
            c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, 1)",
                      (DEFAULT_ADMIN_EMAIL, admin_hash))

        c.execute("SELECT 1 FROM users WHERE email=?", (DEFAULT_USER_EMAIL,))
        if not c.fetchone():
            c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, 0)",
                      (DEFAULT_USER_EMAIL, user_hash))

        conn.commit()

def verify_user(email, password):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, is_admin FROM users WHERE email=? AND password_hash=?",
                  (email, hash_password(password)))
        return c.fetchone()

def add_user(email, password, is_admin=0):
    with get_conn() as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                      (email, hash_password(password), is_admin))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

def get_all_users():
    with get_conn() as conn:
        return pd.read_sql_query("SELECT id, email, is_admin, created_at FROM users", conn)

def delete_user(user_id):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()

def add_keyword(user_id, keyword, target_url):
    target_domain = urlparse(target_url).netloc.replace("www.", "").lower()
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
        INSERT OR IGNORE INTO keywords (user_id, keyword, target_url, target_domain) 
        VALUES (?, ?, ?, ?)
        """, (user_id, keyword.strip(), target_url.strip(), target_domain))
        conn.commit()

def get_user_keywords(user_id):
    with get_conn() as conn:
        return pd.read_sql_query("SELECT * FROM keywords WHERE user_id=?", conn, params=(user_id,))

def save_ranking(keyword_id, rank_position, url, title, features):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO rankings (keyword_id, rank_position, url, page_title, features) 
        VALUES (?, ?, ?, ?, ?)
        """, (keyword_id, rank_position, url, title, json.dumps(features)))
        conn.commit()

def get_ranking_history(keyword_id):
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM rankings WHERE keyword_id=? ORDER BY checked_at ASC", conn, params=(keyword_id,))
        if not df.empty:
            df['checked_at'] = pd.to_datetime(df['checked_at'])
            df['rank_position'] = df['rank_position'].apply(lambda x: x if x <= 100 else 101)
        return df

# ------------------------
# SCRAPER AND PARSER
# ------------------------
def scrape_google_rankings(keyword: str, target_domain: str, retries=3):
    search_url = f"https://www.google.com/search?q={quote_plus(keyword)}&num=100&hl=en&gl=in"
    api_url = f"https://api.scraperapi.com?api_key={SCRAPER_API_KEY}&url={quote_plus(search_url)}&country_code=in"
    
    for attempt in range(retries):
        try:
            r = requests.get(api_url, timeout=60)
            r.raise_for_status()
            return parse_google_results(r.text, target_domain)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(random.uniform(2, 5))
            else:
                st.error(f"Failed to fetch SERP for '{keyword}' after {retries} attempts.")
                return None
    return None

def parse_google_results(html: str, target_domain: str):
    soup = BeautifulSoup(html, "lxml")
    features = []

    # AI Overview
    if soup.find(string=lambda s: s and ("AI Overview" in s or "Overview generated by AI" in s)):
        features.append("AI Overview")
    # People Also Ask
    if soup.find(string=lambda s: s and "People also ask" in s):
        features.append("People Also Ask")
    # Featured Snippet
    if soup.find("div", class_="thODed") or soup.find("div", {"data-attrid": "hw:Featured Snippet"}):
        features.append("Featured Snippet")
    # Knowledge Panel
    if soup.find("div", class_="vk_c") or soup.find("div", {"data-attrid": "hw:Knowledge Panel"}):
        features.append("Knowledge Panel")

    organic_results = []
    rank = 1
    for g in soup.select("div.g"):
        a = g.select_one("a[href]")
        h3 = g.select_one("h3")
        if a and h3 and "google.com" not in a["href"] and not g.select("div[data-text-ad]"):
            href = a["href"]
            if href.startswith("/url?"):
                href = parse_qs(urlparse(href).query).get("q", [""])[0]
            title = h3.get_text(strip=True)
            domain = urlparse(href).netloc.replace("www.", "").lower()
            organic_results.append({"rank": rank, "url": href, "title": title, "domain": domain})
            rank += 1
            if rank > 100:
                break

    result = {"rank": 101, "url": "Not found", "title": "Not in top 100", "features": features}
    for res in organic_results:
        if target_domain in res["domain"]:
            result = {"rank": res["rank"], "url": res["url"], "title": res["title"], "features": features}
            break
    return result

# ------------------------
# UI COMPONENTS
# ------------------------
def login_page():
    st.title("SEO Rank Tracker Login")
    st.caption("Track Google rankings in India (Top 100) with SERP features")

    col1, col2 = st.columns([1, 1])
    with col1:
        email = st.text_input("Email", key="login_email")
    with col2:
        password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login", type="primary", use_container_width=True):
        user = verify_user(email, password)
        if user:
            st.session_state.logged_in = True
            st.session_state.user_id = user[0]
            st.session_state.is_admin = bool(user[1])
            st.session_state.email = email
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Invalid credentials!")

def dashboard_view():
    st.header("Dashboard")
    keywords = get_user_keywords(st.session_state.user_id)
    if keywords.empty:
        st.info("No keywords added yet. Go to **Add Keywords** to get started.")
        return

    # Summary
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Keywords", len(keywords))
    with col2:
        ranked = sum(1 for _, row in keywords.iterrows() if not get_ranking_history(row['id']).empty)
        st.metric("Tracked", ranked)
    with col3:
        st.metric("Last Check", "Never" if ranked == 0 else get_ranking_history(keywords.iloc[0]['id']).iloc[-1]['checked_at'].strftime("%b %d"))

    st.markdown("---")
    for _, row in keywords.iterrows():
        with st.expander(f"**{row['keyword']}** | Target: `{row['target_url']}`"):
            data = get_ranking_history(row['id'])
            if not data.empty:
                latest = data.iloc[-1]
                rank = latest['rank_position']
                rank_display = f"#{rank}" if rank <= 100 else "Not in Top 100"
                st.metric("Current Rank", rank_display, delta=None)

                feats = json.loads(latest['features']) if latest['features'] else []
                if feats:
                    st.caption("**SERP Features:** " + " | ".join(feats))

                # Trend Chart
                chart_df = data[["checked_at", "rank_position"]].set_index("checked_at")
                st.line_chart(chart_df, use_container_width=True, height=200)
            else:
                st.caption("No ranking data yet. Run a check.")

def add_keyword_view():
    st.header("Add Keywords")
    tab1, tab2, tab3 = st.tabs(["Manual", "CSV Upload", "Copy-Paste"])

    with tab1:
        keyword = st.text_input("Keyword", placeholder="btech in biotechnology")
        url = st.text_input("Target URL", placeholder="https://your-site.com/page")
        if st.button("Add Keyword", type="primary"):
            if keyword and url:
                add_keyword(st.session_state.user_id, keyword, url)
                st.success("Keyword added!")
                st.rerun()
            else:
                st.warning("Both fields required.")

    with tab2:
        uploaded = st.file_uploader("Upload CSV", type="csv", help="Columns: keyword, target_url")
        if uploaded and st.button("Import CSV"):
            df = pd.read_csv(uploaded)
            added = 0
            for _, row in df.iterrows():
                if 'keyword' in row and 'target_url' in row:
                    add_keyword(st.session_state.user_id, str(row['keyword']), str(row['target_url']))
                    added += 1
            st.success(f"Added {added} keywords!")
            st.rerun()

    with tab3:
        paste = st.text_area("Paste keywords (one per line)", height=150,
                             placeholder="btech in biotechnology,https://yoursite.com\nmtech biotech,https://yoursite.com/mtech")
        if paste and st.button("Add from Paste"):
            lines = [l.strip() for l in paste.split("\n") if l.strip()]
            added = 0
            for line in lines:
                parts = line.split(",", 1)
                if len(parts) == 2:
                    add_keyword(st.session_state.user_id, parts[0].strip(), parts[1].strip())
                    added += 1
            st.success(f"Added {added} keywords!")
            st.rerun()

def check_rankings_view():
    st.header("Check Rankings")
    keywords = get_user_keywords(st.session_state.user_id)
    if keywords.empty:
        st.info("Add keywords first.")
        return

    selected = st.multiselect("Select keywords to check", keywords["keyword"].tolist(), default=keywords["keyword"].tolist()[:5])
    if st.button("Run Check", type="primary"):
        if not selected:
            st.warning("Select at least one keyword.")
            return

        progress = st.progress(0)
        status = st.empty()
        for i, kw in enumerate(selected):
            row = keywords[keywords["keyword"] == kw].iloc[0]
            status.info(f"Checking: {kw}...")
            res = scrape_google_rankings(row["keyword"], row["target_domain"])
            if res:
                save_ranking(row["id"], res["rank"], res["url"], res["title"], res["features"])
                rank_text = f"**{kw}**: #{res['rank']}" if res['rank'] <= 100 else f"**{kw}**: Not in top 100"
                st.success(rank_text)
                if res["features"]:
                    st.caption("Features: " + " | ".join(res["features"]))
            else:
                st.error(f"Failed: {kw}")
            time.sleep(random.uniform(2, 5))
            progress.progress((i + 1) / len(selected))
        status.success("All done!")
        st.success("Rankings updated!")
        st.rerun()

def admin_panel():
    st.header("Admin Panel")
    if not st.session_state.get("is_admin"):
        st.error("Access denied.")
        return

    users = get_all_users()
    st.subheader("All Users")
    st.dataframe(users)

    st.subheader("Add New User")
    col1, col2 = st.columns(2)
    with col1:
        new_email = st.text_input("Email")
    with col2:
        new_pass = st.text_input("Password", type="password")
    make_admin = st.checkbox("Admin?")
    if st.button("Create User"):
        if new_email and new_pass:
            if add_user(new_email, new_pass, 1 if make_admin else 0):
                st.success("User created!")
                st.rerun()
            else:
                st.error("Email already exists.")
        else:
            st.warning("Fill all fields.")

    st.subheader("Delete User")
    del_id = st.selectbox("Select User ID", users["id"].tolist())
    if st.button("Delete User", type="secondary"):
        delete_user(del_id)
        st.success("User deleted!")
        st.rerun()

# ------------------------
# MAIN
# ------------------------
def main():
    init_db()

    # Initialize login state
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    # === SIDEBAR ===
    if "email" in st.session_state:
        st.sidebar.success(f"Logged in as: **{st.session_state.email}**")
    else:
        st.sidebar.write("Logged in")

    if st.sidebar.button("Logout"):
        for key in ["logged_in", "user_id", "is_admin", "email"]:
            if key in st.session_state:
                del st.session_state[key]
        st.success("Logged out!")
        st.rerun()

    # === NAVIGATION ===
    tabs = ["Dashboard", "Add Keywords", "Check Rankings"]
    if st.session_state.get("is_admin"):
        tabs.append("Admin Panel")

    choice = st.sidebar.radio("Menu", tabs)

    if choice == "Dashboard":
        dashboard_view()
    elif choice == "Add Keywords":
        add_keyword_view()
    elif choice == "Check Rankings":
        check_rankings_view()
    elif choice == "Admin Panel":
        admin_panel()

if __name__ == "__main__":
    main()
