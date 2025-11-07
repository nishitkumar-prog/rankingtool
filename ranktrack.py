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
from datetime import datetime

# ------------------------
# CONFIG
# ------------------------
st.set_page_config(page_title="SEO Rank Tracker", page_icon="📈", layout="wide")

SCRAPER_API_KEY = (
    os.environ.get("SCRAPER_API_KEY")
    or (st.secrets.get("SCRAPER_API_KEY") if hasattr(st, "secrets") else "")
)

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

def add_keyword(user_id, keyword, target_url):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO keywords (user_id, keyword, target_url) VALUES (?, ?, ?)",
                  (user_id, keyword, target_url))
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
        return pd.read_sql_query("SELECT * FROM rankings WHERE keyword_id=? ORDER BY checked_at DESC", conn, params=(keyword_id,))

# ------------------------
# SCRAPER AND PARSER
# ------------------------
def scrape_google_rankings(keyword: str, target_url: str):
    """Fetch Google results using ScraperAPI and parse."""
    if not SCRAPER_API_KEY:
        st.error("No Scraper API key configured. Add SCRAPER_API_KEY in Streamlit secrets.")
        return None

    search_url = f"https://www.google.com/search?q={quote_plus(keyword)}&num=100&hl=en&gl=in"
    api_url = f"https://api.scraperapi.com?api_key={SCRAPER_API_KEY}&url={quote_plus(search_url)}"

    try:
        r = requests.get(api_url, timeout=60)
        r.raise_for_status()
    except Exception as e:
        st.error(f"Error fetching SERP: {e}")
        return None

    return parse_google_results(r.text, target_url)

def parse_google_results(html: str, target_url: str):
    """Parse real Google SERP HTML for organic ranking."""
    soup = BeautifulSoup(html, "lxml")
    target_domain = urlparse(target_url).netloc.replace("www.", "").lower()

    result = {"rank": 101, "url": target_url, "title": "Not found in top 100", "features": []}

    # SERP features
    if soup.find(string=lambda s: s and "People also ask" in s):
        result["features"].append("People Also Ask")
    if soup.find("div", class_="V3FYCf") or soup.find(string=lambda s: "snippet" in s.lower()):
        result["features"].append("Featured Snippet")

    # Extract all organic links
    organic_links = []
    for a in soup.select("a[href]"):
        href = a["href"]
        if href.startswith("/url?"):
            href = parse_qs(urlparse(href).query).get("q", [""])[0]
        if "google.com" not in href and href.startswith("http"):
            organic_links.append(href)

    rank = 1
    for link in organic_links:
        domain = urlparse(link).netloc.replace("www.", "").lower()
        if target_domain and target_domain in domain:
            result["rank"] = rank
            result["url"] = link
            result["title"] = link.split("/")[2]
            break
        rank += 1
        if rank > 100:
            break

    return result

# ------------------------
# UI COMPONENTS
# ------------------------
def login_page():
    st.title("🔐 SEO Rank Tracker Login")
    email = st.text_input("Username", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", type="primary"):
        user = verify_user(email, password)
        if user:
            st.session_state.logged_in = True
            st.session_state.user_id = user[0]
            st.session_state.is_admin = bool(user[1])
            st.session_state.email = email
            st.success("Login successful!")
        else:
            st.error("Invalid credentials!")

def dashboard_view():
    st.header("📊 Dashboard")
    keywords = get_user_keywords(st.session_state.user_id)
    if keywords.empty:
        st.info("No keywords added yet.")
        return

    for _, row in keywords.iterrows():
        with st.expander(f"🔑 {row['keyword']} | 🎯 {row['target_url']}"):
            data = get_ranking_history(row['id'])
            if not data.empty:
                latest = data.iloc[0]
                st.metric("Current Rank", f"#{latest['rank_position']}")
                try:
                    feats = json.loads(latest['features']) if latest['features'] else []
                except:
                    feats = []
                if feats:
                    st.caption("SERP Features: " + ", ".join(feats))
            else:
                st.caption("No ranking data yet. Run a check.")

def add_keyword_view():
    st.header("➕ Add Keywords")
    keyword = st.text_input("Keyword")
    url = st.text_input("Target URL")
    if st.button("Add Keyword"):
        if keyword and url:
            add_keyword(st.session_state.user_id, keyword, url)
            st.success("Keyword added successfully!")
        else:
            st.warning("Please fill both fields.")

def check_rankings_view():
    st.header("🔍 Check Rankings")
    keywords = get_user_keywords(st.session_state.user_id)
    if keywords.empty:
        st.info("Add keywords first.")
        return

    selected = st.multiselect("Select keywords to check:", keywords["keyword"].tolist())
    if st.button("Run Check"):
        if not selected:
            st.warning("Please select at least one keyword.")
            return

        progress = st.progress(0)
        for i, kw in enumerate(selected):
            row = keywords[keywords["keyword"] == kw].iloc[0]
            res = scrape_google_rankings(row["keyword"], row["target_url"])
            if res:
                save_ranking(row["id"], res["rank"], res["url"], res["title"], res["features"])
                rank_text = f"✅ {kw}: Found at #{res['rank']}" if res["rank"] <= 100 else f"🔴 {kw}: Not in top 100"
                st.info(rank_text)
                if res["features"]:
                    st.caption("SERP Features: " + ", ".join(res["features"]))
            else:
                st.error(f"Failed for {kw}")
            progress.progress((i + 1) / len(selected))
            time.sleep(0.5)
        st.success("✅ All rankings checked!")

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

    st.sidebar.write(f"👤 {st.session_state.email}")
    if st.sidebar.button("Logout"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.experimental_rerun()

    tab = st.sidebar.radio("Navigation", ["Dashboard", "Add Keywords", "Check Rankings"])
    if tab == "Dashboard":
        dashboard_view()
    elif tab == "Add Keywords":
        add_keyword_view()
    else:
        check_rankings_view()

if __name__ == "__main__":
    main()
