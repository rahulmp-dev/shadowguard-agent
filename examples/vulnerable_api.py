import sqlite3
import os
from fastapi import FastAPI, Request

app = FastAPI()

# ANTI-PATTERN 1: Hardcoded credentials
DATABASE_URL = "postgresql://admin:password123@prod-db.internal:5432/maindb"
SECRET_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT_SECRET = "super-secret-jwt-key-never-share-this"


def get_db():
    """Get database connection with hardcoded path."""
    return sqlite3.connect("/var/data/production.db")


# ANTI-PATTERN 2: SQL injection via string formatting
@app.get("/users/{user_id}")
async def get_user(user_id: str):
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    result = cursor.fetchone()
    db.close()
    return {"user": result}


# ANTI-PATTERN 3: No input validation on request body
@app.post("/users")
async def create_user(request: Request):
    body = await request.json()
    db = get_db()
    cursor = db.cursor()
    # Direct string interpolation with unvalidated input
    query = f"""INSERT INTO users (name, email, role)
               VALUES ('{body['name']}', '{body['email']}', '{body.get('role', 'user')}')"""
    cursor.execute(query)
    db.commit()
    db.close()
    return {"status": "created"}


# ANTI-PATTERN 4: Mass assignment — accepting arbitrary fields
@app.put("/users/{user_id}")
async def update_user(user_id: str, request: Request):
    body = await request.json()
    db = get_db()
    cursor = db.cursor()
    set_clauses = ", ".join([f"{k} = '{v}'" for k, v in body.items()])
    query = f"UPDATE users SET {set_clauses} WHERE id = '{user_id}'"
    cursor.execute(query)
    db.commit()
    db.close()
    return {"status": "updated"}


# ANTI-PATTERN 5: N+1 query pattern
@app.get("/teams")
async def get_teams():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM teams")
    teams = cursor.fetchall()
    result = []
    for team in teams:
        cursor.execute(f"SELECT * FROM users WHERE team_id = '{team[0]}'")
        members = cursor.fetchall()
        result.append({"team": team, "members": members})
    db.close()
    return {"teams": result}


# ANTI-PATTERN 6: Logging sensitive data
@app.post("/login")
async def login(request: Request):
    body = await request.json()
    print(f"Login attempt: username={body['username']}, password={body['password']}")
    query = f"SELECT * FROM users WHERE username = '{body['username']}' AND password = '{body['password']}'"
    db = get_db()
    cursor = db.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    db.close()
    if user:
        return {"token": SECRET_KEY}
    return {"error": "Invalid credentials"}
