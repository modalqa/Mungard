// Intentionally vulnerable Express server (test fixture).
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const db = require("./db");

const app = express();
app.use(express.json());

app.get("/api/users", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});

app.get("/api/ping", (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));
});

app.get("/api/download", (req, res) => {
  const file = path.join(__dirname, "uploads", req.query.file);
  fs.readFile(file, (err, data) => res.send(data));
});

app.get("/api/proxy", async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

app.get("/go", (req, res) => {
  res.redirect(req.query.next);
});

app.post("/api/login", (req, res) => {
  const token = jwt.sign({ sub: req.body.user }, "super-secret-signing-key");
  res.cookie("session", token, { httpOnly: false });
  res.json({ token });
});

app.post("/api/settings", (req, res) => {
  const settings = {};
  _.merge(settings, req.body);
  res.json(settings);
});

app.post("/api/calc", (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

app.listen(4000);
