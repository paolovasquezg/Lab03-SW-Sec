# Laboratory 03: Software Security

We will revise software security in this lab by running a vulnerable app and its fixed/secure counterpart. Before starting, run:

```bash
make
```

This will build and run both apps:

- VulnerableApp: http://localhost:8000
- FixedApp: http://localhost:8001


## Question 01

Both the vulnerable and secure apps are developed using FastAPI and PostgreSQL. In both we use this user schema:

```
id: int
username: str
name: str
age: int
```

When each app is loaded, we connect to a basic PostgreSQL database:

```
postgresql://postgres:1234@localhost:5432/postgres
```

And execute the following function to insert records/users to test:

```python
def init_db():
	SQLModel.metadata.create_all(engine)

	with Session(engine) as session:
		has_one = session.exec(select(Users).limit(1)).first()
		if not has_one:
			users = [
				Users(username="alice", name="Alice Johnson", age=28),
				Users(username="bob", name="Bob Smith", age=32),
				Users(username="carol", name="Carol Davis", age=25),
				Users(username="dave", name="Dave Wilson", age=40),
				Users(username="eve", name="Eve Martinez", age=22),
				Users(username="frank", name="Frank Brown", age=35),
				Users(username="grace", name="Grace Lee", age=27),
				Users(username="heidi", name="Heidi Clark", age=30),
				Users(username="ivan", name="Ivan Garcia", age=29),
				Users(username="judy", name="Judy Kim", age=26),
			]
			session.add_all(users)
			session.commit()
```

See `fixedapp/db.py` or `vulnapp/db.py` for more detail.


## Vulnerable Application

This application has two endpoints:

```python
@app.get("/ping")
def ping(host: str):
	command = f"ping -c 1 {host}"
    
	try:
		output = subprocess.getoutput(command)
		return {"command": command, "output": output}
    
	except Exception as e:
		return {"command": command, "error": str(e)}
```

This allows direct command injection. And also:

```python
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
```

Which directly allows SQL injection. See `vulnapp/main.py`.


## Fixed Application

To fix the problems, we define these two regexes (see `fixedapp/logger.py`):

```python
sql_injection_detect = re.compile(
	r"(?i)"
	r"("
	r"(?:['\";]|--|/\*|\*/|&&|\|)|"
	r"\bunion\s+select\b|"
	r"\bor\s*'?1'?\s*=\s*'?1'?\b|"
	r"\band\s*'?1'?\s*=\s*'?1'?\b|"
	r"(?:\b(select|insert|update|delete|drop|alter|create)\b.*\b(from|into|table)\b)"
	r")"
)

ip_injection_detect = re.compile(r"(?:['\";]|--|/\*|\*/|&&|\|)")
```

Which allow the following endpoint to detect a possible command injection:

```python
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
```

And in this to detect possible SQL injection:

```python
@app.get("/user")
def user(request: Request, username: str):
    
	query = "SELECT id, username, name, age FROM users WHERE username = %s"

	if sql_injection_detect.search((username or "").lower()):
		ip = request.client.host if request.client else "unknown"
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
```

See `fixedapp/main.py`.


## Question 02

The vulnerable and secure applications are in `vulnapp/` and `fixedapp/` respectively. You can execute both with:

```bash
make
```

This will run both apps:

- VulnerableApp: http://localhost:8000
- FixedApp: http://localhost:8001

Or separately:

```bash
cd vulnapp
fastapi dev main.py
```

```bash
cd fixedapp
fastapi dev main.py
```

In both cases the default is http://localhost:8000 when run directly with `fastapi dev`.


## Question 03

We can test both applications:

- VulnerableApp: http://localhost:8000/user?username=alice
- FixedApp: http://localhost:8001/user?username=alice

Results:

VulnerableApp:

```json
{"query":"SELECT * FROM users WHERE username = 'alice'","rows":[{"id":1,"username":"alice","name":"Alice Johnson","age":28}]}
```

FixedApp:

```json
{"query":"SELECT id, username, name, age FROM users WHERE username = %s","rows":[{"id":1,"username":"alice","name":"Alice Johnson","age":28}]}
```


## Question 04

We can try possible injections in both applications.

### Vulnerable App

This application doesn’t resist any of the following injections.

```
/user?username=' OR '1'='1
```

Result:

```json
{"query":"SELECT * FROM users WHERE username = '' OR '1'= '1'","rows":[{"id":1,"username":"alice","name":"Alice Johnson","age":28},{"id":2,"username":"bob","name":"Bob Smith","age":32},{"id":3,"username":"carol","name":"Carol Davis","age":25},{"id":4,"username":"dave","name":"Dave Wilson","age":40},{"id":5,"username":"eve","name":"Eve Martinez","age":22},{"id":6,"username":"frank","name":"Frank Brown","age":35},{"id":7,"username":"grace","name":"Grace Lee","age":27},{"id":8,"username":"heidi","name":"Heidi Clark","age":30},{"id":9,"username":"ivan","name":"Ivan Garcia","age":29},{"id":10,"username":"judy","name":"Judy Kim","age":26}]}
```

```
/ping?host=127.0.0.1; ls -o
```

Sample result (abridged):

```json
{"command":"ping -c 1 127.0.0.1; ls -o","output":"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.043 ms\n..."}
```

```
/ping?host=127.0.0.1 && id
```

Sample result (abridged):

```json
{"command":"ping -c 1 127.0.0.1 ","output":"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.140 ms\n..."}
```

### Fixed App

This application fixes the previous problems.

```
/user?username=' OR '1'='1
```

Result:

```json
{"error":"invalid query"}
```

```
/ping?host=127.0.0.1; ls -o
```

Result:

```json
{"error":"invalid host"}
```

```
/ping?host=127.0.0.1 && id
```

Result:

```json
{"error":"invalid host"}
```


## Questions 05 & 06

In addition to the security added for the Fixed App, we have added logs using a logger with the following.

### Detailed log line

We log every call to the application with this:

```python
response = await call_next(request)
logger.info(
	f"request ip={ip} endpoint={endpoint} status={response.status_code} user_agent=\"{ua}\" params={params} suspicious={suspicious}"
)
```

Which ends up being logged like this:

```
2025-10-21T23:44:21-0500 INFO request ip=127.0.0.1 endpoint=/user status=200 user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" params={'username': 'alice'} suspicious=False
```

### IDS rules

We define these three rules:

```
sus_threshold = 3 
sus_window = 20
block_duration = 30
```

Which means that if an origin is detected as suspicious 3 times in a row in less than 20 seconds, this origin will be blocked for 30 seconds. The suspicion detection is done this way:

```python
if ip_injection_detect.search(text) or sql_injection_detect.search(text):
	suspicious = True
```

So then if a request is detected as suspicious, it is logged this way:

```python
logger.warning(f"suspicious ip={ip} endpoint={endpoint} user_agent=\"{ua}\" params={params} matches={matches} count={len(q)}")
```

And if the origin is detected suspicious more times than the threshold, it is logged this way:

```python
logger.error(
	f"ids_block ip={ip} endpoint={endpoint} user_agent=\"{ua}\" reason=threshold_exceeded window={sus_window}s block={block_duration}s"
)
```

And when consulted the user obtains this response:

```json
{ "detail": "Temporarily blocked due to suspicious activity" }
```

### Command and SQL injection detection

Individually in the `/ping` and `/user` endpoints injections are detected and logged in the following ways:

`/ping`

```python
if ip_injection_detect.search((host or "").lower()):
	logger.warning(f"validation_cmdinj endpoint=/ping host=\"{host}\"")
	return {"error": "invalid host"}
```

`/user`

```python
if sql_injection_detect.search((username or "").lower()):
	ip = request.client.host
	logger.warning(f"validation_sql ip={ip} endpoint=/user username=\"{username}\"")
	return {"error": "invalid query"}
```

And in the logger independently it is done this way:

```python
if ip_injection_detect.search(text) or sql_injection_detect.search(text):
	suspicious = True
```

### Logs

Following the explanations above, logs can be seen like this:

```
2025-10-21T12:45:43-0500 WARNING suspicious ip=127.0.0.1 endpoint=/ping user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" params={'host': '127.0.0.1;ls'} matches={'host': '127.0.0.1;ls'} count=1
2025-10-21T12:45:43-0500 WARNING validation_cmdinj endpoint=/ping host="127.0.0.1;ls"
2025-10-21T12:45:43-0500 INFO request ip=127.0.0.1 endpoint=/ping status=200 user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" params={'host': '127.0.0.1;ls'} suspicious=True
...
2025-10-21T23:45:55-0500 ERROR ids_block ip=127.0.0.1 endpoint=/user user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" reason=threshold_exceeded window=20s block=30s
```

See `fixedapp/main.py` and `fixedapp/logger.py` for more detail.


### View logs in Docker

You can check the logs of the Docker execution with:

```bash
docker logs -f fixedapp-container
```

Revise `fixedapp/main.py` and `fixedapp/logger.py` for more detail.


## Question 07

## References


