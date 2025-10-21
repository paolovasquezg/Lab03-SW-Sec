from typing import Union
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from db import init_db, engine
import subprocess

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan, title="Vulnapp")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")

def testing():
    return "Testing VulnApp"

@app.get("/ping")
def ping(host: str):
    command = f"ping -c 1 {host}"
    
    try:
        output = subprocess.getoutput(command)
        return {"command": command, "output": output}
    
    except Exception as e:
        return {"command": command, "error": str(e)}


@app.get("/user")
def user(username: str):
    
    query = f"SELECT * FROM users WHERE username = '{username}'"

    conn = engine.raw_connection()
    
    try:
        cur = conn.cursor()
        cur.execute(query)
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return {"query": query, "rows": rows}
    
    except Exception as e:
        
        return {"query": query, "error": str(e)}
    finally:
        conn.close()
