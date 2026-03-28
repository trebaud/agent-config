# Dangerous sink patterns by language

Use these patterns to discover entry points and trace attacker-controlled input to dangerous sinks.

---

## Entry point discovery

### Node.js / Express
```
grep -rn "router\.\(get\|post\|put\|delete\|patch\)" --include="*.js" --include="*.ts"
grep -rn "app\.\(get\|post\|put\|delete\)" --include="*.js" --include="*.ts"
grep -rn "req\.body\|req\.query\|req\.params\|req\.headers" --include="*.js" --include="*.ts"
```

### Python / Django
```
grep -rn "path\|url\|re_path" urls.py */urls.py
grep -rn "request\.GET\|request\.POST\|request\.data\|request\.query_params" --include="*.py"
```

### Python / Flask / FastAPI
```
grep -rn "@app\.route\|@router\.\|@bp\.route" --include="*.py"
grep -rn "request\.args\|request\.form\|request\.json\|request\.files" --include="*.py"
```

### Java / Spring
```
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" --include="*.java"
grep -rn "@RequestParam\|@PathVariable\|@RequestBody\|@RequestHeader" --include="*.java"
```

### PHP / Laravel
```
grep -rn "Route::\(get\|post\|put\|delete\)" routes/*.php
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|request()->\|Input::" --include="*.php"
```

### Go / Gin / Echo
```
grep -rn "\.GET\|\.POST\|\.PUT\|\.DELETE\|\.Handle" --include="*.go"
grep -rn "c\.Param\|c\.Query\|c\.Bind\|r\.FormValue\|r\.URL\.Query" --include="*.go"
```

---

## Dangerous sinks by vulnerability class

### Command injection

| Language | Sink Pattern |
|----------|-------------|
| Node.js | `child_process.exec(`, `child_process.execSync(`, `spawn(` with `shell: true` |
| Python | `os.system(`, `subprocess.run(` with `shell=True`, `subprocess.Popen(` with `shell=True` |
| PHP | `exec(`, `passthru(`, `shell_exec(`, `system(`, `popen(` |
| Java | `Runtime.getRuntime().exec(`, `new ProcessBuilder(` |
| Go | `exec.Command(` with user input in args |

### SQL injection

| Language | Sink Pattern |
|----------|-------------|
| Node.js | `.query(` with string concat, `knex.raw(`, `sequelize.query(` with interpolation |
| Python | `.execute(f"`, `.execute("..."+`, `cursor.execute("...%s" % var)` |
| PHP | `mysql_query(`, `mysqli_query(` without prepared statements |
| Java | `Statement.execute(` with string concat (missing `PreparedStatement`) |
| Go | `db.Query("SELECT..."+userInput)`, `db.Exec(` with `fmt.Sprintf` |

### XSS (server-side rendering)

| Language | Sink Pattern |
|----------|-------------|
| Node.js/EJS | `<%- variable %>` (unescaped), `res.send('<html>' + input)` |
| Python/Jinja2 | `{{ var \| safe }}`, `Markup(user_input)` |
| PHP/Blade | `{!! $variable !!}` (unescaped), `echo $_GET[` |
| Java/JSP | `<%= request.getParameter("x") %>` without encoding |

### XSS (client-side)

| Pattern | Risk |
|---------|------|
| `innerHTML = input` | Direct DOM XSS |
| `document.write(input)` | Direct DOM XSS |
| `eval(input)` | Code execution |
| `v-html="userInput"` | Vue unescaped rendering |
| `dangerouslySetInnerHTML={{__html: input}}` | React escape hatch |

### SSRF

| Language | Sink Pattern |
|----------|-------------|
| Node.js | `axios.get(userUrl)`, `fetch(userUrl)`, `http.get(userUrl)` |
| Python | `requests.get(url)`, `urllib.request.urlopen(url)` |
| Java | `new URL(userInput).openConnection()`, `RestTemplate.getForObject(url,...)` |
| PHP | `file_get_contents($url)`, `curl_setopt($ch, CURLOPT_URL, $url)` |

### Path traversal / LFI

| Language | Sink Pattern |
|----------|-------------|
| Node.js | `fs.readFile(path)`, `fs.readFileSync(path)`, `res.sendFile(path)` |
| Python | `open(path)`, `send_file(path)`, `send_from_directory(dir, filename)` |
| PHP | `include($path)`, `require($path)`, `file_get_contents($path)` |
| Java | `new File(userInput)`, `Paths.get(userInput)`, `FileInputStream(path)` |

### Deserialization

| Language | Sink Pattern |
|----------|-------------|
| Python | `pickle.loads(`, `yaml.load(` without SafeLoader |
| Java | `ObjectInputStream.readObject(`, `XMLDecoder(` |
| PHP | `unserialize(` |
| Node.js | `node-serialize`, `cryo` (known vulnerable libraries) |

### SSTI (server-side template injection)

| Language | Sink Pattern |
|----------|-------------|
| Python/Jinja2 | `render_template_string(user_input)` |
| Python/Mako | `Template(user_input).render()` |
| Node.js/Pug | `pug.render(user_input)` |
| Java/Freemarker | `new Template("t", new StringReader(input), cfg)` |

---

## Secret and credential patterns

```
# API keys and tokens
grep -rn -i "api_key\|apikey\|api-key\|secret_key\|access_key\|auth_token" --include="*.js" --include="*.py" --include="*.go" --include="*.java" --include="*.php"

# AWS access keys (AKIA + 16 alphanumeric)
grep -rn "AKIA[A-Z0-9]\{16\}" .

# Hardcoded passwords
grep -rn -i "password\s*=\s*['\"][^'\"]\{6,\}" --include="*.js" --include="*.py" --include="*.php"

# Private keys
grep -rn "BEGIN.*PRIVATE KEY" .

# .env files present in repo
find . -name ".env*" -not -path "./.git/*" -not -path "*/node_modules/*"
```

---

## Auth/authz review patterns

```
# JWT handling
grep -rn "jwt\|jsonwebtoken\|PyJWT\|jose\|jws" --include="*.js" --include="*.py" -l

# Auth middleware attachment
grep -rn "authenticate\|authorize\|requireAuth\|login_required\|@login_required\|isAuthenticated" --include="*.js" --include="*.py" --include="*.rb" --include="*.go"

# User ID in queries (IDOR surface)
grep -rn "user_id\|userId\|owner_id\|account_id" --include="*.js" --include="*.py" --include="*.go"

# Role checks
grep -rn "role\|isAdmin\|is_admin\|has_permission\|authorize\|can(" --include="*.js" --include="*.py"
```
