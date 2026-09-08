import fs from "node:fs";
import path from "node:path";

const BASE = "http://127.0.0.1:3000/api";
const mode = process.argv.includes("--mode")
  ? process.argv[process.argv.indexOf("--mode") + 1]
  : "unknown";

if (!BASE.startsWith("http://127.0.0.1") && !BASE.startsWith("http://localhost")) {
  console.error("Refusing to run against a non-localhost target.");
  process.exit(1);
}

const evidenceDir = path.resolve("evidence", "harness");
fs.mkdirSync(evidenceDir, { recursive: true });

const results = [];
function record(id, name, exploited, detail) {
  results.push({ id, name, exploited, detail });
  console.log(`  [${id}] ${exploited ? "EXPLOITED" : "BLOCKED"} - ${name}`);
  if (detail) console.log(`         ${detail}`);
}

function cookieFrom(res) {
  const raw = res.headers.get("set-cookie") || "";
  const csrf = /sd_csrf=([^;,]+)/.exec(raw)?.[1] ?? "";
  const refresh = /sd_refresh=([^;,]+)/.exec(raw)?.[1] ?? "";
  return { csrf, refresh, header: `sd_csrf=${csrf}; sd_refresh=${refresh}` };
}

async function login(email, password) {
  const res = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json();
  return { token: body.accessToken, cookies: cookieFrom(res) };
}

async function main() {
  console.log(`\nSecureDocs attack harness - target ${BASE} - mode: ${mode}\n`);
  const owner = await login("owner@securedocs.test", "Passw0rd!Demo");
  const user = await login("user@securedocs.test", "Passw0rd!Demo");

  let uploadedStorageKey = null;

  // VULN-01: unrestricted upload
  try {
    const fd = new FormData();
    fd.set("file", new Blob(["not a real executable"]), "harness.exe");
    fd.set("title", "harness VULN-01");
    fd.set("description", "attack harness");
    fd.set("category", "Test");
    const res = await fetch(`${BASE}/documents`, {
      method: "POST",
      headers: { Authorization: `Bearer ${owner.token}`, "X-CSRF-Token": owner.cookies.csrf, Cookie: owner.cookies.header },
      body: fd,
    });
    const accepted = res.status === 201;
    if (accepted) {
      const b = await res.json();
      uploadedStorageKey = b.document?.originalName ?? null;
    }
    record("VULN-01", "Unrestricted file upload (.exe)", accepted, `HTTP ${res.status}`);
  } catch (e) { record("VULN-01", "Unrestricted file upload (.exe)", false, String(e)); }

  // VULN-02: IDOR
  try {
    const res = await fetch(`${BASE}/documents/legacy/1/download`, { headers: { Authorization: `Bearer ${user.token}` } });
    record("VULN-02", "IDOR - read another user document", res.status === 200, `HTTP ${res.status} as standard user`);
  } catch (e) { record("VULN-02", "IDOR - read another user document", false, String(e)); }

  // VULN-03: privilege escalation
  try {
    const res = await fetch(`${BASE}/admin/users`, { headers: { Authorization: `Bearer ${user.token}`, "X-User-Role": "ADMINISTRATOR" } });
    record("VULN-03", "Privilege escalation via X-User-Role", res.status === 200, `HTTP ${res.status} reaching admin route`);
  } catch (e) { record("VULN-03", "Privilege escalation via X-User-Role", false, String(e)); }

  // VULN-04: plaintext at rest — only meaningful if THIS run's upload was accepted
  try {
    if (!uploadedStorageKey) {
      record("VULN-04", "Plaintext storage at rest", false, "upload was rejected, nothing stored this run");
    } else {
      const blob = path.resolve("apps/api/storage/blobs", uploadedStorageKey);
      const exploited = fs.existsSync(blob) && fs.readFileSync(blob, "utf8").includes("not a real executable");
      record("VULN-04", "Plaintext storage at rest", exploited, exploited ? "plaintext readable on disk" : "stored blob is encrypted");
    }
  } catch (e) { record("VULN-04", "Plaintext storage at rest", false, String(e)); }

  // VULN-05: predictable / non-revocable token
  try {
    const list = await (await fetch(`${BASE}/documents?scope=owned`, { headers: { Authorization: `Bearer ${owner.token}` } })).json();
    const docId = list.items?.[0]?.id;
    const createRes = await fetch(`${BASE}/documents/${docId}/share`, {
      method: "POST",
      headers: { Authorization: `Bearer ${owner.token}`, "X-CSRF-Token": owner.cookies.csrf, Cookie: owner.cookies.header, "Content-Type": "application/json" },
      body: JSON.stringify({ expiresInHours: 1, canDownload: true, singleUse: false }),
    });
    const created = await createRes.json();
    const token = created.token ?? "";
    const shortToken = token.length > 0 && token.length < 30;
    await fetch(`${BASE}/share/${created.shareLink.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${owner.token}`, "X-CSRF-Token": owner.cookies.csrf, Cookie: owner.cookies.header },
    });
    const afterRevoke = await fetch(`${BASE}/share/${token}`);
    const worksAfterRevoke = afterRevoke.status === 200;
    record("VULN-05", "Predictable / non-revocable share token", shortToken || worksAfterRevoke, `token length ${token.length}, works after revoke: ${worksAfterRevoke}`);
  } catch (e) { record("VULN-05", "Predictable / non-revocable share token", false, String(e)); }

  // VULN-06: silent logging — perform a download THIS run, then check it was logged
  try {
    const list = await (await fetch(`${BASE}/documents?scope=owned`, { headers: { Authorization: `Bearer ${owner.token}` } })).json();
    const docId = list.items?.[0]?.id;
    // owner downloads their own document — always authorised, so this isolates logging
    await fetch(`${BASE}/documents/${docId}/download`, { headers: { Authorization: `Bearer ${owner.token}` } });
    const auditor = await login("auditor@securedocs.test", "Passw0rd!Demo");
    const res = await fetch(`${BASE}/audit?eventType=DOC_DOWNLOAD`, { headers: { Authorization: `Bearer ${auditor.token}` } });
    const body = await res.json();
    const total = body.total ?? 0;
    record("VULN-06", "Download not recorded in audit log", total === 0, `DOC_DOWNLOAD records after a download: ${total}`);
  } catch (e) { record("VULN-06", "Download not recorded in audit log", false, String(e)); }

  const exploited = results.filter((r) => r.exploited).length;
  console.log(`\n  ${exploited}/${results.length} vulnerabilities EXPLOITED in ${mode} mode\n`);
  const out = path.join(evidenceDir, `results-${mode}.json`);
  fs.writeFileSync(out, JSON.stringify({ mode, target: BASE, results }, null, 2));
  console.log(`  Results written to ${out}\n`);
}

main().catch((e) => { console.error(e); process.exit(1); });