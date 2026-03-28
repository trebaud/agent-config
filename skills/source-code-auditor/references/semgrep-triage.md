# Semgrep output triage -- false positive elimination

Semgrep is a pattern matcher, not a dataflow analyzer. It produces leads, not verdicts. Every alert must be manually validated before reporting.

---

## Triage decision tree

For each semgrep finding, walk this tree top-to-bottom. First match wins.

```
Alert received
  |
  +--> Is the matched code in tests, fixtures, mocks, or dev-only paths?
  |      YES --> DISCARD (not production code)
  |
  +--> Is the matched code dead/unreachable? (no route, no caller, feature-flagged off)
  |      YES --> DISCARD (unreachable code)
  |
  +--> Does the framework auto-protect against this class?
  |      YES --> Is the code using the safe API? (e.g., ORM .find() vs raw query)
  |               YES --> DISCARD (framework-protected)
  |               NO  --> NEEDS REVIEW (opted out of protection)
  |
  +--> Is the input actually attacker-controlled?
  |      NO  --> DISCARD (server-generated, hardcoded, or internal-only)
  |      YES --> Continue
  |
  +--> Read 30+ lines of context. Is there sanitization between source and sink?
  |      YES --> Is the sanitization bypassable?
  |               NO  --> DISCARD (sanitized)
  |               MAYBE --> NEEDS REVIEW (test bypass)
  |      NO  --> Continue
  |
  +--> Does exploitation require unrealistic conditions?
  |      YES --> DISCARD (requires admin, MitM, physical access, etc.)
  |
  +--> TRUE POSITIVE --- proceed to validation
```

---

## Common false positive patterns by rule category

### SQL Injection Rules (`sqli`, `sql-injection`)
**Common FPs:**
- ORM method calls (`Model.findOne()`, `User.objects.filter()`) --- ORMs parameterize by default
- Query builders with bound parameters (`knex('table').where('id', id)`)
- String concatenation in logging/debug statements, not actual queries
- Template literals used only for table/column names (not user input)
- Raw queries with hardcoded values (no user input in the string)

**True positive signals:**
- `db.query("SELECT * FROM users WHERE id = " + req.params.id)`
- `cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")`
- `knex.raw(...)` or `sequelize.query(...)` with string interpolation of user input
- Any raw SQL with string concatenation/interpolation of request parameters

### XSS Rules (`xss`, `cross-site-scripting`)
**Common FPs:**
- React/Vue/Angular components (auto-escape by default)
- Server-side template engines with auto-escaping enabled (Jinja2 `{{ var }}`, Django templates, EJS `<%= %>`)
- API-only endpoints returning JSON (Content-Type: application/json)
- Values rendered inside JavaScript strings that are JSON-encoded

**True positive signals:**
- `innerHTML = userInput`, `document.write(userInput)`, `v-html="userInput"`
- `res.send('<div>' + req.query.name + '</div>')`
- Template engines with escaping disabled: `<%- var %>` (EJS), `{{ var | safe }}` (Jinja2), `{!! $var !!}` (Blade)
- `dangerouslySetInnerHTML` with unsanitized input

### Command Injection Rules (`command-injection`, `os-command`)
**Common FPs:**
- `child_process.exec()` with hardcoded commands (no user input)
- `subprocess.run()` with argument lists (not shell=True)
- Commands using `shlex.quote()` or `shellescape` on user input
- Exec calls inside Docker/CI build scripts (not reachable from web)

**True positive signals:**
- `exec("ping " + req.query.host)` --- direct concatenation
- `os.system(f"nslookup {domain}")` with `domain` from request
- `subprocess.run(cmd, shell=True)` where `cmd` contains user input
- Any shell command built from string concatenation/interpolation with request data

### SSRF Rules (`ssrf`, `server-side-request-forgery`)
**Common FPs:**
- URL construction using hardcoded base URLs with only path segments from user
- Webhook URLs stored in admin-only settings
- Internal service-to-service calls using service discovery (no user input)
- Fetch calls with URL allowlists validated before request

**True positive signals:**
- `fetch(req.body.url)` or `requests.get(user_url)` with no URL validation
- URL validation that only checks prefix (bypassable: `http://evil.com#@allowed.com`)
- Allowlist bypass via DNS rebinding, redirects, or IPv6/decimal IP encoding

### Path Traversal Rules (`path-traversal`, `lfi`)
**Common FPs:**
- `path.join(__dirname, 'static', filename)` where `express.static` handles serving
- File access with basename extraction: `path.basename(userInput)`
- Paths validated against allowlist of filenames
- OS-level protections (chroot, containerized filesystem)

**True positive signals:**
- `fs.readFile('/uploads/' + req.params.file)` with no `..` filtering
- `open(os.path.join(base_dir, user_input))` without `os.path.realpath` check
- `res.sendFile(req.query.path)` with no path normalization

### Deserialization Rules (`deserialization`)
**Common FPs:**
- `JSON.parse()` --- safe, not object deserialization
- `yaml.safe_load()` (Python) --- safe loader
- Deserialization of server-generated data (session stores with HMAC)
- Protobuf/MessagePack parsing (typed, no code execution)

**True positive signals:**
- `pickle.loads(request.data)` --- arbitrary code execution
- `yaml.load(data)` without `Loader=yaml.SafeLoader`
- `ObjectInputStream.readObject()` on user-supplied data
- `unserialize($_GET['data'])` in PHP

---

## Adversarial re-evaluation checklist

After initial triage, run this checklist on every surviving finding to catch remaining FPs:

- [ ] **Would a junior dev writing this code have intended it to be safe?** If the code looks intentionally guarded but semgrep can't see it, investigate the guard.
- [ ] **Is this a known semgrep rule limitation?** Some rules match patterns without tracking dataflow. Check if the rule's metadata says "pattern-based" vs "taint-mode".
- [ ] **Does the matched code have a test that exercises the security path?** If an integration test sends malicious input and expects rejection, the defense likely works.
- [ ] **Is there middleware/interceptor that applies globally?** Express middleware, Django middleware, Spring filters --- these are invisible to per-file pattern matching.
- [ ] **Am I assuming the absence of a defense means it's absent?** Read the framework docs if unsure. Many frameworks enable security features by default.

---

## Triage output format

For every semgrep alert, record the verdict:

```
| # | Rule ID | File:Line | Verdict | Reason |
|---|---------|-----------|---------|--------|
```

Verdicts: `TRUE POSITIVE` | `FALSE POSITIVE` | `NEEDS REVIEW`

Every FALSE POSITIVE must have a one-line reason -- so reviewers can verify your work.
