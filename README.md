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

## Question 07

We will see the importance of applying the following techniques to avoid attacks and vulnerabilities:

### SQL

Directly concatenating queries like:

```python
query = f"SELECT * FROM users WHERE username = '{username}'"
```

can directly permit injection as it was shown before. Using parameterized queries like:

```
SELECT id, username, name, age FROM users WHERE username = %s
```

makes the database treat the parameters received only as values, so the attacker can’t change the query structure [1]. For example in the endpoint `/user`, using this directly compares `username` with the parameter sent. ORMs, like in the example below [2], apply this same principle:

```python
user_id = request.args.get('user_id')
user = db.session.query(User).filter_by(id=user_id).first()
```

### b. Command

By concatenating strings into commands, an attacker can inject any command they want into the system [3]. For example, in the vulnerable app:

```python
command = f"ping -c 1 {host}"
```

This allows injecting additional commands. To fix this, we use `subprocess.run([...])` [4], like:

```python
command = ["ping", "-c", "1", "-W", "2", host]
res = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
```

This makes the user input be treated completely as data, so there’s no interpretation of characters like `;` or other shell operators. This complements the idea of not permitting `shell=True` [5], which allows Python to run commands through a shell and parse operators like `&&` or `;`, making injection possible.

### c. Validation and whitelisting

Validating helps avoid attacks and injections by only accepting what’s supposed to be accepted. Within this, there’s blacklisting (blocks known bad inputs/patterns) and whitelisting (only allows known safe inputs). In our implementation we apply blacklisting with these patterns:

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

Why is whitelisting better than blacklisting? In this case we choose to do blacklisting, but actually whitelisting is safer because attackers can often find new ways to bypass blacklists, while with whitelisting this is much harder [6].

### d. Least privilege

Giving the least privilege to the accounts used by the application and database is very important. Why? For example, if an attacker is able to inject SQL but the DB user only has read access, they won’t be able to modify or delete information, reducing the impact. In our case, for example in the vulnerable application:

```python
query = f"SELECT * FROM users WHERE username = '{username}'"
```

is akin to giving the user only read access and nothing else, so the injection is not as dangerous as it could be [7].

### e. Rotation and cipher

Managing backups and rotating credentials is very beneficial. For credentials, suppose a user is able to do injection on a database with write/delete access. When this suspicious access is detected, the state of the database can be recovered via the backups (assuming these backups are done on a daily basis). For rotating credentials, suppose an attacker gains access, for example to the database as in our case:

```
postgresql://postgres:1234@localhost:5432/postgres
```

Where the password is `1234`. If we are constantly rotating passwords and credentials, we could, for example, change the password to `5678` and the attacker loses access.

And for all this to be safer, we should protect these backups and credentials—preferably encrypted [8].

### f. Additional mitigations

Using a Web Application Firewall (WAF) can be highly effective for filtering and controlling incoming traffic by allowing only trusted IP addresses to connect [9]. In addition, rate limiting and CAPTCHA mechanisms are valuable for preventing abuse of endpoints that are susceptible to spamming or brute-force attacks. In particular, Google reCAPTCHA v3 helps identify non-human interactions and block automated requests, ensuring that only legitimate users can access critical endpoints [10]. Finally, Multi-Factor Authentication (MFA) plays a crucial role in protecting sensitive operations such as login processes, by adding an additional layer of verification that significantly reduces the risk of unauthorized access [11].

## References

1. Parker, J. (2011, January 17). What is parameterized query?. Stack Overflow. https://stackoverflow.com/questions/4712037/what-is-parameterized-query
2. Zakrzewski, S. (2025, April 28). SQL Injection in the Age of ORM: Risks, Mitigations, and Best Practices. AFINE. https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices/
3. OWASP Foundation. (n.d.). Command Injection. OWASP. https://owasp.org/www-community/attacks/Command_Injection
4. Python Software Foundation. (n.d.). subprocess — Subprocess management. Python Documentation. https://docs.python.org/3/library/subprocess.html
5. Python Software Foundation. (n.d.). subprocess — Frequently used arguments (warning: shell=True security hazard). Python Documentation. https://docs.python.org/3/library/subprocess.html#frequently-used-arguments
6. OWASP Foundation. (n.d.). Input Validation. OWASP. https://owasp.org/www-community/Input_Validation
7. Palo Alto Networks. (n.d.). What is the principle of least privilege? Palo Alto Networks Cyberpedia. https://www.paloaltonetworks.com/cyberpedia/what-is-the-principle-of-least-privilege
8. CIS Controls. (n.d.). Control 11 — Data Recovery. Center for Internet Security. https://www.cisecurity.org/controls/data-recovery/
9. Cloudflare. (n.d.). What is a Web Application Firewall (WAF)? https://www.cloudflare.com/learning/ddos/what-is-a-web-application-firewall-waf/
10. Google. (n.d.). reCAPTCHA v3. https://developers.google.com/recaptcha/docs/v3
11. Microsoft. (n.d.). What is multi-factor authentication? Microsoft Learn. https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks


