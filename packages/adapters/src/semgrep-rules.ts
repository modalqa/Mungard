/**
 * Mungard's bundled Semgrep rules for JavaScript / TypeScript / Next.js.
 * Licensed Apache-2.0 with the rest of Mungard, so the default static scan
 * works offline and without the Semgrep Registry (whose rules are under the
 * Semgrep Rules License, which restricts some commercial uses).
 */
export const MUNGARD_SEMGREP_RULES = `
rules:
  - id: mungard.js.eval-injection
    languages: [javascript, typescript]
    severity: ERROR
    message: Dynamic code evaluation with a non-literal argument. If any part of it is user-controlled this is remote code execution.
    metadata: { cwe: ["CWE-95"], confidence: MEDIUM, category: security }
    pattern-either:
      - patterns:
          - pattern: eval($X)
          - pattern-not: eval("...")
      - patterns:
          - pattern: new Function(..., $X)
          - pattern-not: new Function(..., "...")

  - id: mungard.js.child-process-injection
    languages: [javascript, typescript]
    severity: ERROR
    message: A shell command is built from interpolated or concatenated values. Use execFile/spawn with an argument array and validate input.
    metadata: { cwe: ["CWE-78"], confidence: MEDIUM, category: security }
    pattern-either:
      - pattern: $CP.exec(\`...\${$X}...\`, ...)
      - pattern: $CP.execSync(\`...\${$X}...\`, ...)
      - pattern: exec(\`...\${$X}...\`, ...)
      - pattern: execSync(\`...\${$X}...\`, ...)
      - pattern: $CP.exec("..." + $X, ...)
      - pattern: $CP.execSync("..." + $X, ...)
      - pattern: exec("..." + $X, ...)
      - pattern: execSync("..." + $X, ...)
      - pattern: "$CP.spawn($CMD, $ARGS, {..., shell: true, ...})"

  - id: mungard.js.sql-injection
    languages: [javascript, typescript]
    severity: ERROR
    message: SQL is built with string interpolation or concatenation. Use parameterized queries or the query builder's placeholders.
    metadata: { cwe: ["CWE-89"], confidence: MEDIUM, category: security }
    pattern-either:
      - pattern: $DB.query(\`...\${$X}...\`, ...)
      - pattern: $DB.query("..." + $X, ...)
      - pattern: $DB.execute(\`...\${$X}...\`, ...)
      - pattern: $DB.execute("..." + $X, ...)
      - pattern: $DB.raw(\`...\${$X}...\`, ...)
      - pattern: $DB.$queryRawUnsafe(\`...\${$X}...\`, ...)
      - pattern: $DB.$executeRawUnsafe(\`...\${$X}...\`, ...)
      - pattern: $DB.$queryRawUnsafe("..." + $X, ...)
      - pattern: $DB.$executeRawUnsafe("..." + $X, ...)

  - id: mungard.js.nosql-injection
    languages: [javascript, typescript]
    severity: WARNING
    message: A database query object comes straight from the request. Attackers can inject operators such as $ne or $where. Validate and pick fields explicitly.
    metadata: { cwe: ["CWE-943"], confidence: MEDIUM, category: security }
    patterns:
      - pattern-either:
          - patterns:
              - pattern-either:
                  - pattern: $COLL.$FIND($REQ.body, ...)
                  - pattern: $COLL.$FIND($REQ.query, ...)
              - metavariable-regex:
                  metavariable: $REQ
                  regex: ^(req|request|ctx|c|event|r)$
          - pattern: "$COLL.$FIND({..., $where: $X, ...}, ...)"
      - metavariable-regex:
          metavariable: $FIND
          regex: ^(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)$

  - id: mungard.react.dangerously-set-inner-html
    languages: [javascript, typescript]
    severity: WARNING
    message: dangerouslySetInnerHTML with a non-literal value can lead to XSS. Sanitize with a vetted library (for example DOMPurify) or render text instead.
    metadata: { cwe: ["CWE-79"], confidence: LOW, category: security }
    patterns:
      - pattern: "{__html: $X}"
      - pattern-not: '{__html: "..."}'

  - id: mungard.js.inner-html-assignment
    languages: [javascript, typescript]
    severity: WARNING
    message: Assigning a non-literal value to innerHTML/outerHTML can lead to XSS.
    metadata: { cwe: ["CWE-79"], confidence: LOW, category: security }
    patterns:
      - pattern-either:
          - pattern: $EL.innerHTML = $X
          - pattern: $EL.outerHTML = $X
      - pattern-not: $EL.innerHTML = "..."
      - pattern-not: $EL.outerHTML = "..."

  - id: mungard.nextjs.public-env-secret
    languages: [javascript, typescript]
    severity: ERROR
    message: A NEXT_PUBLIC_ variable with a secret-looking name is inlined into the client bundle and visible to every visitor. Keep secrets in server-only variables.
    metadata: { cwe: ["CWE-200"], confidence: HIGH, category: security }
    patterns:
      - pattern: process.env.$NAME
      - metavariable-regex:
          metavariable: $NAME
          regex: ^NEXT_PUBLIC_.*(SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|SERVICE_KEY|ADMIN|TOKEN).*$

  - id: mungard.js.jwt-hardcoded-secret
    languages: [javascript, typescript]
    severity: ERROR
    message: A JWT is signed or verified with a hardcoded secret. Load it from a secret store or environment variable, and rotate the current value.
    metadata: { cwe: ["CWE-798"], confidence: HIGH, category: security }
    pattern-either:
      - pattern: $JWT.sign($P, "...", ...)
      - pattern: $JWT.verify($T, "...", ...)

  - id: mungard.js.jwt-insecure-verify
    languages: [javascript, typescript]
    severity: ERROR
    message: JWT verification accepts the "none" algorithm or ignores expiry.
    metadata: { cwe: ["CWE-347"], confidence: HIGH, category: security }
    pattern-either:
      - pattern: '$JWT.verify($T, $K, {..., algorithms: [..., "none", ...], ...}, ...)'
      - pattern: "$JWT.verify($T, $K, {..., ignoreExpiration: true, ...}, ...)"

  - id: mungard.js.jwt-decode-without-verify
    languages: [javascript, typescript]
    severity: INFO
    message: jwt.decode() does not verify the signature. Make sure the result is never used for authentication or authorization decisions.
    metadata: { cwe: ["CWE-345"], confidence: LOW, category: security }
    pattern: jwt.decode(...)

  - id: mungard.js.tls-verification-disabled
    languages: [javascript, typescript]
    severity: WARNING
    message: TLS certificate verification is disabled, which allows man-in-the-middle attacks.
    metadata: { cwe: ["CWE-295"], confidence: HIGH, category: security }
    pattern-either:
      - pattern: "{..., rejectUnauthorized: false, ...}"
      - pattern: process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

  - id: mungard.js.weak-hash
    languages: [javascript, typescript]
    severity: INFO
    message: MD5/SHA-1 are not collision resistant. Do not use them for passwords, signatures or integrity checks; use SHA-256+ or a password hash such as argon2/bcrypt.
    metadata: { cwe: ["CWE-328"], confidence: LOW, category: security }
    pattern-either:
      - pattern: $CRYPTO.createHash("md5")
      - pattern: $CRYPTO.createHash("sha1")

  - id: mungard.js.deprecated-cipher
    languages: [javascript, typescript]
    severity: WARNING
    message: crypto.createCipher/createDecipher derive keys insecurely and are removed in recent Node.js versions. Use createCipheriv with a random IV.
    metadata: { cwe: ["CWE-327"], confidence: HIGH, category: security }
    pattern-either:
      - pattern: $CRYPTO.createCipher(...)
      - pattern: $CRYPTO.createDecipher(...)

  - id: mungard.js.insecure-deserialization
    languages: [javascript, typescript]
    severity: ERROR
    message: node-serialize's unserialize() executes code embedded in the payload.
    metadata: { cwe: ["CWE-502"], confidence: HIGH, category: security }
    pattern-either:
      - pattern: $S.unserialize(...)
      - pattern: unserialize(...)

  - id: mungard.js.cors-credentials-wildcard
    languages: [javascript, typescript]
    severity: WARNING
    message: CORS reflects any origin while allowing credentials, so any website can make authenticated requests and read responses.
    metadata: { cwe: ["CWE-942"], confidence: MEDIUM, category: security }
    pattern-either:
      - pattern: "cors({..., origin: true, ..., credentials: true, ...})"
      - pattern: "cors({..., credentials: true, ..., origin: true, ...})"
      - pattern: "cors({..., origin: '*', ..., credentials: true, ...})"
      - pattern: "cors({..., credentials: true, ..., origin: '*', ...})"

  - id: mungard.js.cookie-insecure-flags
    languages: [javascript, typescript]
    severity: WARNING
    message: A cookie is set with httpOnly or secure explicitly disabled. Session cookies should be httpOnly, secure and SameSite.
    metadata: { cwe: ["CWE-1004", "CWE-614"], confidence: MEDIUM, category: security }
    pattern-either:
      - pattern: "$RES.cookie($N, $V, {..., httpOnly: false, ...})"
      - pattern: "$RES.cookie($N, $V, {..., secure: false, ...})"
      - pattern: "$C.set($N, $V, {..., httpOnly: false, ...})"

  - id: mungard.js.prototype-pollution-merge
    languages: [javascript, typescript]
    severity: WARNING
    message: Deep-merging request data into an object can allow prototype pollution. Validate the body against a schema first.
    metadata: { cwe: ["CWE-1321"], confidence: LOW, category: security }
    pattern-either:
      - pattern: $L.merge($T, $REQ.body)
      - pattern: $L.defaultsDeep($T, $REQ.body)
      - pattern: $L.set($T, $REQ.body.$K, ...)

  - id: mungard.js.mass-assignment
    languages: [javascript, typescript]
    severity: WARNING
    message: The whole request body is written to the database. Attackers can set fields such as role, ownerId or isAdmin. Pick allowed fields explicitly.
    metadata: { cwe: ["CWE-915"], confidence: LOW, category: security }
    pattern-either:
      - pattern: "$M.create({data: $REQ.body})"
      - pattern: "$M.update({..., data: $REQ.body, ...})"
      - pattern: "$M.create({data: await $REQ.json()})"
      - pattern: "$M.update({..., data: await $REQ.json(), ...})"
      - pattern: $M.create($REQ.body)
      - pattern: $M.findByIdAndUpdate($ID, $REQ.body, ...)

  - id: mungard.js.tainted-path
    languages: [javascript, typescript]
    severity: ERROR
    message: A filesystem path is built from request input, which may allow path traversal. Resolve the path and check it stays inside an allowed directory.
    metadata: { cwe: ["CWE-22"], confidence: MEDIUM, category: security }
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $REQ.query
              - pattern: $REQ.params
              - pattern: $REQ.body
              - pattern: (await $REQ.json())
              - pattern: (await $REQ.formData()).get(...)
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request|ctx|c|event|r)$
      - pattern: $U.searchParams.get(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $FS.$F($P, ...)
          - metavariable-regex:
              metavariable: $F
              regex: ^(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|sendFile)$
          - focus-metavariable: $P

  - id: mungard.js.ssrf
    languages: [javascript, typescript]
    severity: WARNING
    message: An outbound request URL comes from request input (server-side request forgery). Allowlist hosts and block internal and metadata addresses.
    metadata: { cwe: ["CWE-918"], confidence: MEDIUM, category: security }
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $REQ.query
              - pattern: $REQ.params
              - pattern: $REQ.body
              - pattern: (await $REQ.json())
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request|ctx|c|event|r)$
      - pattern: $U.searchParams.get(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: fetch($URL, ...)
              - pattern: axios($URL, ...)
              - pattern: axios.$M($URL, ...)
              - patterns:
                  - pattern-either:
                      - pattern: $HTTP.get($URL, ...)
                      - pattern: $HTTP.request($URL, ...)
                  - metavariable-regex:
                      metavariable: $HTTP
                      regex: ^(http|https|got|request|superagent|ky|needle|undici)$
          - focus-metavariable: $URL

  - id: mungard.js.open-redirect
    languages: [javascript, typescript]
    severity: WARNING
    message: A redirect target comes from request input (open redirect). Only redirect to relative paths or allowlisted hosts.
    metadata: { cwe: ["CWE-601"], confidence: MEDIUM, category: security }
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $REQ.query
              - pattern: $REQ.params
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request|ctx|c|event|r)$
      - pattern: $U.searchParams.get(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $RES.redirect($TARGET)
              - pattern: $RES.redirect($CODE, $TARGET)
              - pattern: redirect($TARGET)
              - pattern: NextResponse.redirect($TARGET, ...)
          - focus-metavariable: $TARGET
`;
