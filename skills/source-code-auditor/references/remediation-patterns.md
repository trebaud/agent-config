# Remediation patterns by vulnerability class

Fix patterns by vuln class. Each one shows the vulnerable code, the fix, and why it works.

---

## SQL Injection

### Fix: parameterized queries (always)

**Node.js (mysql2/pg):**
```javascript
// VULNERABLE
db.query("SELECT * FROM users WHERE id = " + req.params.id);

// FIXED
db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
```

**Python (psycopg2/sqlite3):**
```python
# VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# FIXED
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
```

**Java (JDBC):**
```java
// VULNERABLE
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// FIXED
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setString(1, userId);
```

**Why it works:** Parameterized queries separate SQL structure from data. The database engine never parses user input as SQL syntax.

**Bad fix:** Blocklist filtering (`str.replace("'", "")`) --- always bypassable via encoding, double-encoding, or alternative syntax.

---

## Command injection

### Fix: avoid shell; use argument arrays

**Node.js:**
```javascript
// VULNERABLE
const { exec } = require('child_process');
exec("ping " + req.query.host);

// FIXED
const { execFile } = require('child_process');
execFile("ping", ["-c", "4", req.query.host]);
```

**Python:**
```python
# VULNERABLE
os.system(f"nslookup {domain}")

# FIXED
subprocess.run(["nslookup", domain], capture_output=True, check=True)
# Note: no shell=True, arguments as list
```

**Why it works:** Without `shell=True` / shell invocation, metacharacters (`;`, `|`, `` ` ``, `$()`) are treated as literal arguments, not shell syntax.

**Bad fix:** Blocklist filtering shell metacharacters --- always incomplete. Use `shlex.quote()` only as defense-in-depth, not as primary fix.

---

## XSS (cross-site scripting)

### Fix: context-aware output encoding

**Server-side (EJS):**
```javascript
// VULNERABLE (unescaped)
<%- userInput %>

// FIXED (auto-escaped)
<%= userInput %>
```

**Client-side (DOM):**
```javascript
// VULNERABLE
element.innerHTML = userInput;

// FIXED
element.textContent = userInput;
```

**React:**
```jsx
// VULNERABLE
<div dangerouslySetInnerHTML={{__html: userInput}} />

// FIXED --- use a sanitizer if HTML is required
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

**Why it works:** Output encoding converts dangerous characters (`<`, `>`, `"`, `'`, `&`) into their HTML entity equivalents at render time. `textContent` never interprets HTML.

**Bad fix:** Input-side filtering/stripping HTML tags --- bypassable via encoding, mutation XSS, or context-specific payloads. Always encode at output, not input.

---

## SSRF (server-side request forgery)

### Fix: URL allowlisting + DNS resolution validation

```javascript
// VULNERABLE
const response = await fetch(req.body.url);

// FIXED
const { URL } = require('url');
const dns = require('dns').promises;

const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];

async function safeFetch(urlString) {
  const parsed = new URL(urlString);

  // Protocol allowlist
  if (!['https:', 'http:'].includes(parsed.protocol)) {
    throw new Error('Invalid protocol');
  }

  // Host allowlist
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    throw new Error('Host not allowed');
  }

  // Resolve DNS to prevent rebinding to internal IPs
  const addresses = await dns.resolve4(parsed.hostname);
  for (const addr of addresses) {
    if (isPrivateIP(addr)) throw new Error('Internal IP blocked');
  }

  return fetch(urlString);
}
```

**Why it works:** Validates protocol, hostname against allowlist, and resolved IP against private ranges --- blocks direct SSRF, DNS rebinding, and protocol smuggling.

**Bad fix:** Blocklisting `127.0.0.1` / `localhost` only --- bypassable via `0x7f000001`, `[::1]`, decimal IP, DNS rebinding, or redirect chains.

---

## Path traversal / LFI

### Fix: resolve and validate against base directory

**Node.js:**
```javascript
// VULNERABLE
const filePath = path.join('/uploads', req.params.filename);
fs.readFile(filePath, callback);

// FIXED
const requestedPath = path.resolve('/uploads', req.params.filename);
if (!requestedPath.startsWith('/uploads/')) {
  return res.status(403).send('Forbidden');
}
fs.readFile(requestedPath, callback);
```

**Python:**
```python
# VULNERABLE
filepath = os.path.join(base_dir, user_filename)
return send_file(filepath)

# FIXED
filepath = os.path.realpath(os.path.join(base_dir, user_filename))
if not filepath.startswith(os.path.realpath(base_dir) + os.sep):
  abort(403)
return send_file(filepath)
```

**Why it works:** `path.resolve()` / `os.path.realpath()` canonicalizes `../` sequences, then the prefix check ensures the final path stays within the allowed directory.

**Bad fix:** Stripping `../` from input --- bypassable via `....//`, URL encoding (`%2e%2e%2f`), or null bytes on some systems.

---

## Deserialization

### Fix: never deserialize untrusted data; use safe formats

**Python:**
```python
# VULNERABLE
data = pickle.loads(request.data)

# FIXED --- use JSON instead
data = json.loads(request.data)

# If YAML is needed:
# VULNERABLE
data = yaml.load(content)
# FIXED
data = yaml.safe_load(content)
```

**Java:**
```java
// VULNERABLE
ObjectInputStream ois = new ObjectInputStream(userInputStream);
Object obj = ois.readObject();

// FIXED --- use JSON/allowlist
ObjectMapper mapper = new ObjectMapper();
MyDto dto = mapper.readValue(userInput, MyDto.class);
```

**Why it works:** JSON/safe loaders only reconstruct data structures, never execute code. Pickle/Java serialization can instantiate arbitrary objects with side effects.

**Bad fix:** Allowlisting classes in deserialization --- complex, error-prone, and new gadget chains regularly bypass allowlists.

---

## SSTI (server-side template injection)

### Fix: never render user input as template source

```python
# VULNERABLE
return render_template_string(user_input)

# FIXED --- pass user input as a variable, not as template source
return render_template_string("{{ content }}", content=user_input)

# BEST --- use a pre-defined template file
return render_template("display.html", content=user_input)
```

**Why it works:** User input as a template variable is escaped by the engine. User input as template source is parsed and executed.

---

## Hardcoded secrets

### Fix: environment variables or secret manager

```javascript
// VULNERABLE
const apiKey = "sk-live-abc123def456";

// FIXED
const apiKey = process.env.API_KEY;
```

```python
# VULNERABLE
SECRET_KEY = "my-secret-key-here"

# FIXED
SECRET_KEY = os.environ["SECRET_KEY"]
```

**Additional steps:**
1. Rotate the exposed credential immediately
2. Add the secret to `.env` (which must be in `.gitignore`)
3. If committed to git history: treat the credential as compromised, rotate it, and consider `git filter-branch` or BFG to remove from history

---

## IDOR / broken access control

### Fix: always scope queries to the authenticated user

```javascript
// VULNERABLE --- any user can access any order
app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

// FIXED --- scoped to authenticated user
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});
```

**Why it works:** Adding the ownership check (`userId: req.user.id`) ensures users can only access their own resources, regardless of what ID they supply.

**Bad fix:** Client-side ID obfuscation (UUIDs instead of integers) --- security through obscurity, UUIDs are still guessable/enumerable.
