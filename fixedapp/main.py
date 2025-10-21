from typing import Union
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from db import init_db, engine
import subprocess
from ipaddress import ip_address, IPv4Address

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan, title="FixedApp")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def testing():
    return "Testing Fixedapp"

@app.get("/ping")
def ping(host: str):
    
    try:
        ip = ip_address(host)
        if not isinstance(ip, IPv4Address):
            return {"error": "invalid IPv4 address"}
    except ValueError:
        return {"error": "invalid IPv4 address"}

    command = ["ping", "-c", "1", host]
    try:
        res = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        return {
            "command": " ".join(command),
            "output": res.stdout
        }
    
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}


@app.get("/user")
def user(username: str):
  
    query = "SELECT id, username, name, age FROM users WHERE username = %s"

    conn = engine.raw_connection()
    cur = None
    try:
        cur = conn.cursor()
        cur.execute(query, (username,))
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return {"query": query, "rows": rows}
    
    except Exception as e:
        return {"query": query, "error": str(e)}
    
    finally:
        try:
            if cur is not None:
                cur.close()
        except Exception:
            pass
        conn.close()
