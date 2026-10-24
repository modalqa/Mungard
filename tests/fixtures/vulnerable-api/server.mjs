// Intentionally vulnerable HTTP API used by Mungard's integration tests and demos.
// DO NOT DEPLOY. Zero dependencies; run with: node tests/fixtures/vulnerable-api/server.mjs [port]
import http from "node:http";

const TOKENS = { "alice-token": "alice", "bob-token": "bob", "admin-token": "admin" };
const ROLES = { alice: "member", bob: "member", admin: "admin" };

const invoices = {
  inv_alice_1: { id: "inv_alice_1", owner: "alice", amount: 120, email: "alice@fixture.test" },
  inv_bob_1: { id: "inv_bob_1", owner: "bob", amount: 80, email: "bob@fixture.test" },
};
const projects = {
  prj_alice: { id: "prj_alice", owner: "alice", name: "Alice secret roadmap" },
};
const orders = new Map();
let nextOrder = 1;

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", "x-powered-by": "FixtureServer/1.0.3", ...headers });
  res.end(JSON.stringify(body));
}

function userOf(req) {
  const auth = req.headers.authorization ?? "";
  return TOKENS[auth.replace(/^Bearer\s+/i, "")];
}

async function readJson(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

export function createServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const user = userOf(req);
    // Vulnerable CORS: reflects any origin with credentials.
    const corsHeaders = req.headers.origin ? { "access-control-allow-origin": req.headers.origin, "access-control-allow-credentials": "true" } : {};

    if (url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html", "set-cookie": "sessionid=abc123; Path=/", "x-powered-by": "FixtureServer/1.0.3", ...corsHeaders });
      return res.end("<html><body><h1>Fixture</h1><a href='/about'>about</a></body></html>");
    }
    if (url.pathname === "/about") {
      res.writeHead(200, { "content-type": "text/html" });
      return res.end("<html><body>About</body></html>");
    }
    if (url.pathname === "/api/me") {
      if (!user) return send(res, 401, { error: "unauthorized" });
      return send(res, 200, { user, role: ROLES[user] }, corsHeaders);
    }
    // Documented as authenticated but forgets to check (authentication bypass).
    if (url.pathname === "/api/reports/summary") {
      return send(res, 200, { revenue: 1000, customers: 2 });
    }
    // BOLA: any authenticated user can read any invoice.
    const inv = url.pathname.match(/^\/api\/invoices\/([\w-]+)$/);
    if (inv) {
      if (!user) return send(res, 401, { error: "unauthorized" });
      const invoice = invoices[inv[1]];
      return invoice ? send(res, 200, invoice) : send(res, 404, { error: "not found" });
    }
    // Correctly protected resource (ownership enforced).
    const prj = url.pathname.match(/^\/api\/projects\/([\w-]+)$/);
    if (prj) {
      if (!user) return send(res, 401, { error: "unauthorized" });
      const p = projects[prj[1]];
      if (!p || (p.owner !== user && ROLES[user] !== "admin")) return send(res, 404, { error: "not found" });
      return send(res, 200, p);
    }
    // Business logic flaw: an unpaid order can be shipped.
    if (url.pathname === "/api/orders" && req.method === "POST") {
      if (!user) return send(res, 401, { error: "unauthorized" });
      const body = await readJson(req);
      const order = { id: `ord_${nextOrder++}`, owner: user, item: body.item ?? "widget", paid: false, status: "created" };
      orders.set(order.id, order);
      return send(res, 201, order);
    }
    const ship = url.pathname.match(/^\/api\/orders\/([\w-]+)\/ship$/);
    if (ship && req.method === "POST") {
      if (!user) return send(res, 401, { error: "unauthorized" });
      const order = orders.get(ship[1]);
      if (!order || order.owner !== user) return send(res, 404, { error: "not found" });
      order.status = "shipped"; // BUG: does not check order.paid
      return send(res, 200, order);
    }
    send(res, 404, { error: "not found" });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.argv[2] ?? 4010);
  createServer().listen(port, "127.0.0.1", () => console.log(`vulnerable-api listening on http://127.0.0.1:${port}`));
}
