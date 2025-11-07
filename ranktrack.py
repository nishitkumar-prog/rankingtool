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
st.set_page_config(page_title="SEO Rank Tracker", page_icon="📈", layout="wide")
SCRAPER_API_KEY = "614a33d52e88c3fd0b15d60520ad3d98"  # Your provided key
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
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            keyword TEXT NOT NULL,
            target_url TEXT NOT NULL,
            target_domain TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
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
        # Default users
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
        c.execute("INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
                  (email, hash_password(password), is_admin))
        conn.commit()

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
        c.execute("INSERT INTO keywords (user_id, keyword, target_url, target_domain) VALUES (?, ?, ?, ?)",
                  (user_id, keyword, target_url, target_domain))
        conn.commit()

def get_user_keywords(user_id):
    with get_conn() as conn:
        return pd.read_sql_query("SELECT * FROM keywords WHERE user_id=?", conn, params=(user_id,))

def save_ranking(keyword_id, rank_position, url, title, features):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO rankings (keyword_id, rank_position, url, page_title, features) VALUES (?, ?, ?, ?, ?)",
                  (keyword_id, rank_position, url, title, json.dumps(features)))
        conn.commit()

def get_ranking_history(keyword_id):
    with get_conn() as conn:
        df = pd.read_sql_query("SELECT * FROM rankings WHERE keyword_id=? ORDER BY checked_at ASC", conn, params=(keyword_id,))
        if not df.empty:
            df['checked_at'] = pd.to_datetime(df['checked_at'])
            df['rank_position'] = df['rank_position'].apply(lambda x: x if x <= 100 else 101)  # Cap at 101 for charts
        return df

# ------------------------
# SCRAPER AND PARSER (Improved)
# ------------------------
def scrape_google_rankings(keyword: str, target_domain: str, retries=3):
    """Fetch Google results using ScraperAPI and parse. Retries on failure."""
    search_url = f"https://www.google.com/search?q={quote_plus(keyword)}&num=100&hl=en&gl=in"
    api_url = f"https://api.scraperapi.com?api_key={SCRAPER_API_KEY}&url={quote_plus(search_url)}&country_code=in"
    
    for attempt in range(retries):
        try:
            r = requests.get(api_url, timeout=60)
            r.raise_for_status()
            return parse_google_results(r.text, target_domain)
        except Exception as e:
            if attempt < retries - 1:
                st.warning(f"Error fetching SERP for '{keyword}' (Attempt {attempt+1}/{retries}): {e}")
                time.sleep(random.uniform(2, 5))  # Rate limit backoff
            else:
                st.error(f"Failed to fetch SERP for '{keyword}' after {retries} attempts.")
                return None
    return None

def parse_google_results(html: str, target_domain: str):
    """Parse Google SERP HTML for organic ranking and features."""
    soup = BeautifulSoup(html, "lxml")
    
    # Detect SERP features
    features = []
    if soup.find("div", {"data-attrid": "hw:Overview"}) or soup.find(string=lambda s: s and "AI Overview" in s):  # AI Overview
        features.append("AI Overview")
    if soup.find("div", {"data-attrid": "hw:Questions & answers"}) or soup.find(string=lambda s: s and "People also ask" in s):  # PAA
        features.append("People Also Ask")
    if soup.find("div", class_="thODed") or soup.find("div", {"data-attrid": "hw:Featured Snippet"}):  # Featured Snippet
        features.append("Featured Snippet")
    if soup.find("div", class_="vk_c") or soup.find("div", {"data-attrid": "hw:Knowledge Panel"}):  # Knowledge Panel
        features.append("Knowledge Panel")
    
    # Extract organic results (div.g, with h3 and a[href])
    organic_results = []
    rank = 1
    for g in soup.select("div.g"):
        a = g.select_one("a[href]")
        h3 = g.select_one("h3")
        if a and h3 and "google.com" not in a["href"] and not g.select("div[data-text-ad]"):  # Organic only, skip ads
            href = a["href"]
            if href.startswith("/url?"):
                href = parse_qs(urlparse(href).query).get("q", [""])[0]
            title = h3.text.strip() if h3 else "No Title"
            domain = urlparse(href).netloc.replace("www.", "").lower()
            organic_results.append({"rank": rank, "url": href, "title": title, "domain": domain})
            rank += 1
            if rank > 100:
                break
    
    # Find matching rank
    result = {"rank": 101, "url": "Not found", "title": "Not found in top 100", "features": features}
    for res in organic_results:
        if target_domain in res["domain"]:
            result = {"rank": res["rank"], "url": res["url"], "title": res["title"], "features": features}
            break
    return result

# ------------------------
# UI COMPONENTS
# ------------------------
def login_page():
    st.title("🔐 SEO Rank Tracker Login")
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", type="primary"):
        user = verify_user(email, password)
        if user:
            st.session_state.logged_in = True
            st.session_state.user_id = user[0]
            st.session_state.is_admin = bool(user[1])
            st.session_state.email = email  # Ensure this is set
            st.success("Login successful!")
            st.rerun()  # Refresh UI after login
        else:
            st.error("Invalid credentials!")

def dashboard_view():
    st.header("📊 Dashboard")
    keywords = get_user_keywords(st.session_state.user_id)
    if keywords.empty:
        st.info("No keywords added yet.")
        return
    st.dataframe(keywords[["keyword", "target_url", "created_at"]])
    for _, row in keywords.iterrows():
        with st.expander(f"🔑 {row['keyword']} | 🎯 {row['target_url']}"):
            data = get_ranking_history(row['id'])
            if not data.empty:
                latest = data.iloc[-1]  # Latest is last (ASC order)
                rank_display = f"#{latest['rank_position']}" if latest['rank_position'] <= 100 else "Not in Top 100"
                st.metric("Latest Rank", rank_display)
                feats = json.loads(latest['features']) if latest['features'] else []
                if feats:
                    st.caption("SERP Features: " + ", ".join(feats))
                # Trend chart
                trend_df = data[["checked_at", "rank_position"]].set_index("checked_at")
                st.line_chart(trend_df, use_container_width=True, height=200)
            else:
                st.caption("No ranking data yet. Run a check.")

def add_keyword_view():
    st.header("➕ Add Keywords")
    tab1, tab2, tab3 = st.tabs(["Manual", "CSV Upload", "Copy-Paste"])
    
    with tab1:
        keyword = st.text_input("Keyword")
        url = st.text_input("Target URL")
        if st.button("Add Single Keyword"):
            if keyword and url:
                add_keyword(st.session_state.user_id, keyword, url)
                st.success("Keyword added!")
                st.rerun()
            else:
                st.warning("Please fill both fields.")

    with tab2:
        uploaded_file = st.file_uploader("Upload CSV (columns: keyword, target_url)", type="csv")
        if uploaded_file and st.button("Add from CSV"):
            df = pd.read_csv(uploaded_file)
            added_count = 0
            for _, row in df.iterrows():
                if 'keyword' in row and 'target_url' in row and pd.notna(row['keyword']) and pd.notna(row['target_url']):
                    add_keyword(st.session_state.user_id, row['keyword'], row['target_url'])
                    added_count += 1
            st.success(f"Added {added_count} keywords!")
            st.rerun()

    with tab3:
        paste = st.text_area("Paste keywords (one per line: keyword,target_url)")
        if paste and st.button("Add from Paste"):
            lines = paste.strip().split("\n")
            added_count = 0
            for line in lines:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == 2 and parts[0] and parts[1]:
                    add_keyword(st.session_state.user_id, parts[0], parts[1])
                    added_count += 1
            st.success(f"Added {added_count} keywords!")
            st.rerun()

def check_rankings_view():
    st.header("🔍 Check Rankings (Daily Manual Run)")
    keywords = get_user_keywords(st.session_state.user_id)
    if keywords.empty:
        st.info("Add keywords first.")
        return
    selected = st.multiselect("Select keywords to check:", keywords["keyword"].tolist())
    if st.button("Run Check"):
        if not selected:
            st.warning("Select at least one keyword.")
            return
        progress = st.progress(0)
        for i, kw in enumerate(selected):
            row = keywords[keywords["keyword"] == kw].iloc[0]
            res = scrape_google_rankings(row["keyword"], row["target_domain"])
            if res:
                save_ranking(row["id"], res["rank"], res["url"], res["title"], res["features"])
                rank_text = f"✅ {kw}: #{res['rank']}" if res["rank"] <= 100 else f"🔴 {kw}: Not in top 100"
                st.info(rank_text)
                if res["features"]:
                    st.caption("Features: " + ", ".join(res["features"]))
            else:
                st.error(f"Failed for {kw}")
            time.sleep(random.uniform(2, 5))  # Rate limit
            progress.progress((i + 1) / len(selected))
        st.success("All checks complete!")
        st.rerun()

def admin_panel():
    st.header("🛡️ Admin Panel")
    users = get_all_users()
    st.dataframe(users)
    
    # Add user
    new_email = st.text_input("New User Email")
    new_pass = st.text_input("New User Password", type="password")
    is_admin = st.checkbox("Make Admin?")
    if st.button("Add User"):
        if new_email and new_pass:
            add_user(new_email, new_pass, 1 if is_admin else 0)
            st.success("User added!")
            st.rerun()
    
    # Delete user
    if not users.empty:
        del_id = st.selectbox("Select User ID to Delete:", users["id"].tolist())
        if st.button("Delete User"):
            delete_user(del_id)
            st.success("User deleted!")
            st.rerun()

# ------------------------
# MAIN
# ------------------------
def main():
    init_db()
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login_page()
        return

    # --- SAFE SIDEBAR ---
    if "email" in st.session_state:
        st.sidebar.write(f"👤 {st.session_state.email}")
    else:
        st.sidebar.write("👤 (unknown)")

    if st.sidebar.button("Logout"):
        keys_to_clear = ["logged_in", "user_id", "is_admin", "email"]
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]
        st.success("Logged out successfully!")
        st.rerun()

    # Navigation
    tabs = ["Dashboard", "Add Keywords", "Check Rankings"]
    if st.session_state.get("is_admin", False):
        tabs.append("Admin Panel")

    tab = st.sidebar.radio("Navigation", tabs)

    if tab == "Dashboard":
        dashboard_view()
    elif tab == "Add Keywords":
        add_keyword_view()
    elif tab == "Check Rankings":
        check_rankings_view()
    elif tab == "Admin Panel" and st.session_state.get("is_admin"):
        admin_panel()

if __name__ == "__main__":
    main()
