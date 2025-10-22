from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from db import init_db, engine
from ipaddress import ip_address, IPv4Address
from logger import Logger, ip_injection_detect, sql_injection_detect, logger
import subprocess


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

app.add_middleware(Logger)

@app.get("/")
def testing():
    return "Testing FixedApp"


@app.get("/ping")
def ping(host: str):
    if ip_injection_detect.search((host or "").lower()):
        logger.warning(f"validation_cmdinj endpoint=/ping host=\"{host}\"")
        return {"error": "invalid host"}
    try:
        ip = ip_address(host)
        if not isinstance(ip, IPv4Address):
            logger.info(f"validation_failed endpoint=/ping reason=not_ipv4 host={host}")
            return {"error": "invalid IPv4 address"}
    except ValueError:
        logger.warning(f"validation_failed endpoint=/ping reason=invalid_ip host={host}")
        return {"error": "invalid IPv4 address"}

    command = ["ping", "-c", "1", "-W", "2", host]
    try:
        res = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        logger.info(f"ping_ok host={host} rc={res.returncode}")
        return {"command": " ".join(command), "output": res.stdout}

    except subprocess.TimeoutExpired:
        logger.warning(f"ping_timeout host={host}")
        return {"error": "timeout"}


@app.get("/user")
def user(request: Request, username: str):
    
    query = "SELECT id, username, name, age FROM users WHERE username = %s"

    if sql_injection_detect.search((username or "").lower()):
        ip = request.client.host
        logger.warning(f"validation_sql ip={ip} endpoint=/user username=\"{username}\"")
        return {"error": "invalid query"}

    conn = engine.raw_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, (username,))
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        logger.info(f"sql_ok endpoint=/user username={username} rows={len(rows)}")
        return {"query": query, "rows": rows}

    except Exception as e:
        logger.exception(f"sql_error endpoint=/user username={username} query=\"{query}\"")
        return {"query": query, "error": str(e)}

    finally:
        conn.close()
