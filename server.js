const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 10000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ppda-admin-2025';
const KEY_SECRET = 'PPDA_UG_REGS2023_AUDIT';
const DB_FILE = path.join(__dirname, 'clients.json');

// ── DATABASE ──────────────────────────────────────────────
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch(e) {}
  return { clients: {}, logs: [] };
}
function saveDB(db) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } catch(e) {}
}

// ── CRYPTO ────────────────────────────────────────────────
function hs(str) {
  return crypto.createHash('sha256').update(str + KEY_SECRET).digest('hex').substring(0, 16).toUpperCase();
}
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'PPDA_SALT_2025').digest('hex');
}
function genKey(days, clientId) {
  const expiry = Date.now() + days * 86400000;
  const sig = hs(clientId + ':' + expiry);
  const payload = clientId + '|' + expiry + '|' + sig;
  const b = Buffer.from(payload).toString('base64')
    .replace(/=/g,'').replace(/\+/g,'A').replace(/\//g,'B');
  const chunks = [];
  for (let i = 0; i < Math.min(b.length, 20); i += 5)
    chunks.push(b.substring(i, i+5).toUpperCase());
  return 'PPDA-' + chunks.join('-');
}
function valKey(key) {
  try {
    const inner = key.replace('PPDA-','').replace(/-/g,'')
      .replace(/A/g,'+').replace(/B/g,'/');
    const pad = inner + '==='.substring(0,(4 - inner.length % 4) % 4);
    const payload = Buffer.from(pad, 'base64').toString('utf8');
    const parts = payload.split('|');
    if (parts.length < 3) return { ok:false, reason:'Malformed key' };
    const clientId = parts[0], expiry = parseInt(parts[1]), sig = parts[2];
    if (sig !== hs(clientId + ':' + expiry)) return { ok:false, reason:'Invalid signature' };
    if (Date.now() > expiry) return { ok:false, reason:'Expired on ' + new Date(expiry).toLocaleDateString() };
    return { ok:true, clientId, expiry, daysLeft: Math.ceil((expiry - Date.now()) / 86400000) };
  } catch(e) { return { ok:false, reason:'Cannot decode key: ' + e.message }; }
}

// ── HELPERS ───────────────────────────────────────────────
function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS,DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-ppda-user,x-ppda-pass,x-admin-secret');
}
function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 10 * 1024 * 1024) reject(new Error('Body too large')); });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch(e) { resolve({}); } });
    req.on('error', reject);
  });
}
function log(db, username, action, detail) {
  db.logs.unshift({ ts: new Date().toISOString(), user: username, action, detail });
  if (db.logs.length > 500) db.logs = db.logs.slice(0, 500);
}
function authClient(req, db) {
  const username = req.headers['x-ppda-user'] || '';
  const password = req.headers['x-ppda-pass'] || '';
  if (username === 'admin' && password === ADMIN_SECRET)
    return { ok:true, username:'admin', role:'admin' };
  const client = db.clients[username];
  if (!client) return { ok:false, reason:'User not found' };
  if (client.passwordHash !== hashPassword(password)) return { ok:false, reason:'Incorrect password' };
  const vr = valKey(client.key);
  if (!vr.ok) return { ok:false, reason:'Access expired: ' + vr.reason };
  return { ok:true, username, role:'client', expiry:vr.expiry, daysLeft:vr.daysLeft };
}

// ── ANTHROPIC CALL ────────────────────────────────────────
function callAnthropic(body) {
  return new Promise((resolve, reject) => {
    if (!ANTHROPIC_API_KEY) return reject(new Error('ANTHROPIC_API_KEY not set in environment variables'));
    const payload = JSON.stringify(body);
    const options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Bad response from Anthropic')); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ── PPDA LEGAL FRAMEWORK ──────────────────────────────────
const PPDA_LAW = `
PPDA ACT 2003 (AS AMENDED 2021) — KEY SECTIONS:
S.3 Objectives: economy, efficiency, competition, fairness, transparency, accountability, non-discrimination
S.14 Procurement Unit: mandatory establishment, staffing, secretariat function
S.15 Contracts Committee: composition, quorum 2/3, approval thresholds, conflict of interest
S.16 Accounting Officer: overall accountability, delegation limits
S.17 User Departments: technical specifications, requisitions, inspection and acceptance
S.18 Evaluation Committee: independence, odd-numbered, expertise, conflict of interest declarations
S.26 Open Domestic Bidding: default method for high-value procurements
S.27 Open International Bidding: cross-border competition
S.28 Restricted Domestic Bidding: limited suppliers, justification required
S.30 Request for Quotations: micro and minor value; minimum 3 quotations
S.31 Direct Procurement (Sole Source): emergency, proprietary, continuation — written justification mandatory
S.31A Direct procurement from manufacturers of aviation, medical, agricultural and industrial equipment (2021 Amendment)
S.36 Procurement Planning: mandatory annual plan, Contracts Committee approval, PPDA website publication
S.37 Specifications: technically neutral, non-discriminatory, performance-based preferred
S.39 Advertisement: PPDA website, national newspapers, notice boards; minimum periods per method
S.40 Bid Security: 1-2% of bid value; bank guarantee or insurance bond
S.41 Bid Opening: public, witnessed, all bids read aloud, signed minutes
S.42 Evaluation: pre-disclosed criteria; preliminary, technical, financial stages; signed report
S.44 Best Evaluated Bidder: 10 working day standstill period before award
S.45 Contract Award: Contracts Committee approval; publication on PPDA website
S.46 Debriefing: right of unsuccessful bidders within 14 days
S.55 Contract Administration: designated contract manager, roles and responsibilities
S.57 Payment: certification prerequisite; within 30 days; interest on late payment
S.58 Variations: written approval; cumulative cap 25% of original contract value
S.59 Termination: grounds, notice, compensation
S.64 Board of Survey: annual; categorisation of assets
S.65 Disposal Methods: public auction, open tender, transfer/donation, trade-in, destruction
S.66 Proceeds: remittance to Consolidated Fund
S.74 Debarment: fraud, corruption, collusion, misrepresentation
S.86 Offences: splitting, falsification, corruption, conflict of interest, bid rigging
S.87 Penalties: fines up to UGX 500M and/or imprisonment up to 10 years
S.90-91 Administrative Review: 2 TIERS ONLY (Accounting Officer then PPDA Appeals Tribunal — 2021 Amendment removed PPDA from review)
S.95 Record Keeping: complete procurement file mandatory; 10-year minimum retention
S.96 Minister issues Regulations on recommendation of PPDA
S.97 Publication of contract awards

PPDA REGULATIONS 2023 — EFFECTIVE 5TH FEBRUARY 2024 (7 SETS replacing 2014 Regulations):

1. PPDA (PROCURING AND DISPOSING ENTITIES) REGULATIONS 2023:
Reg 3: PDE organisational requirements and procurement unit staffing
Reg 4: Contracts Committee procedures, quorum, minutes format, declaration forms
Reg 5: Evaluation Committee composition (minimum 3, odd number), expertise, independence
Reg 6: Conflict of Interest — mandatory written declaration; automatic recusal; referral to Inspector General
Reg 7: Procurement Unit Functions — secretariat, records management, GEPS platform reporting
Reg 8: User Department responsibilities — specifications, requisitions, inspection teams
Reg 9: Accounting Officer delegation matrix
Reg 10: Reservation Schemes — 15% of annual budget reserved for Women, Youth, PWDs associations; local content preferences (2021 Amendment)

2. PPDA (RULES AND METHODS FOR PROCUREMENT OF SUPPLIES, WORKS AND NON-CONSULTANCY SERVICES) REGULATIONS 2023:
Reg 11: Procurement Planning — annual plan format, submission to Contracts Committee by 30 September
Reg 12: Procurement Thresholds (current):
  Micro: up to UGX 5,000,000 — direct purchase, AO appoints handler, 3 written quotes preferred
  Minor Value: UGX 5M–50M — Request for Quotations, minimum 3 quotes
  Restricted Bidding: UGX 50M–500M goods/services; up to UGX 1.5Bn works
  Open Domestic Bidding: above UGX 500M goods/services; above UGX 1.5Bn works
  Open International Bidding: above UGX 5Bn goods/works
Reg 13: Direct Procurement — written Contracts Committee approval; market survey; maximum 3 months
Reg 14: Force Account — Contracts Committee approval; own resources
Reg 15: Advertisement periods — PPDA website mandatory; open domestic minimum 21 days (REDUCED from 2014); restricted minimum 14 days; RFQ 7 days
Reg 16: Bid Documents — PPDA standard documents mandatory
Reg 17: Pre-bid Meetings — minutes issued as addenda to all bidders simultaneously
Reg 18: Bid Submission — sealed; late bids returned unopened
Reg 19: Bid Opening — public; two independent witnesses; all prices read aloud; signed minutes within 24 hours
Reg 20: Bid Validity — minimum 90 days; extension by mutual consent
Reg 21: Bid Security — 1-2% bid price; bank guarantee or PPDA-approved insurance bond; returned within 14 days to unsuccessful bidders
Reg 22: Preliminary Evaluation — mandatory/desirable criteria; pass/fail; non-responsive bids eliminated
Reg 23: Technical Evaluation — minimum qualifying score 70%; signed report
Reg 24: Financial Evaluation — lowest evaluated cost; abnormally low bids require clarification
Reg 25: Evaluation Report — signed by all Evaluation Committee members; submitted to Contracts Committee
Reg 26: Clarifications — written only; no change to bid substance or price
Reg 27: Negotiations — only with best evaluated bidder; scope and technical details only
Reg 28: Contract Award Notification — 10 working day standstill; publication on PPDA website
Reg 29: Contract Signing — after standstill; performance security lodged first
Reg 30: Performance Security — 5-10% contract value; bank guarantee; valid until final completion
Reg 31: Advance Payment — maximum 20% standard; up to 100% with Attorney General approval AND PS/ST authorisation
Reg 32: Contract Variations — written; Contracts Committee approval; cumulative cap 25% original value
Reg 33: Extension of Time — justified; written; approved before original expiry; liquidated damages applied for delay
Reg 34: Inspection and Acceptance — user department; independent inspector for contracts above UGX 500M
Reg 35: Payment Certification — inspection certificate prerequisite; payment within 30 days; interest at Bank of Uganda rate
Reg 36: Retention Money — 5-10%; 50% released on practical completion; balance on final completion
Reg 37: Liquidated Damages — rate stated in contract; applied automatically; cap typically 10%
Reg 38: Contract Closure — final account; completion certificate; performance evaluation submitted to PPDA
Reg 39: ESHS (Environmental, Social and Health Safeguards) — NEW 2023 — mandatory clause in ALL contracts; compliance monitored during execution
Reg 40: Sustainable Procurement — NEW 2023 — preference for environmentally friendly goods/services; lifecycle costing permitted

3. PPDA (PROCUREMENT OF CONSULTANCY SERVICES) REGULATIONS 2023:
Reg 41: Consultancy Selection Methods — QCBS (default), QBS, FBS, LCS, CQS, SSS
Reg 42: Expression of Interest — advertised; shortlist 5-7 firms
Reg 43: Request for Proposals — technical and financial proposals; separate sealed envelopes
Reg 44: Technical Evaluation — completed before financial opened; minimum qualifying score 75% (INCREASED from 70% in 2014)
Reg 45: Financial Opening — only firms above minimum technical score; prices read publicly
Reg 46: Combined Score — QCBS typically 80% technical : 20% financial
Reg 47: Negotiations — with top-ranked firm on scope, methodology, staffing — NOT fees for QCBS
Reg 48: Individual Consultants — CVs evaluated; lump sum contract
Reg 49: Consultancy Records — all evaluation sheets, declarations, proposals retained

4. PPDA (DISPOSAL OF PUBLIC ASSETS) REGULATIONS 2023:
Reg 50: Annual Board of Survey — mandatory; interdepartmental; report to Accounting Officer
Reg 51: Disposal Plan — assets listed; method recommended; Contracts Committee approval
Reg 52: Public Auction — licensed auctioneer; reserve price disclosed; proceeds to Consolidated Fund within 5 days
Reg 53: Open Tender for Disposal — standard process; award to highest responsive offer
Reg 54: Transfer/Donation — valuation by Chief Government Valuer; approval; eligibility criteria
Reg 55: Trade-in — market value assessed; Contracts Committee approval
Reg 56: Destruction — witnessed; certificate signed; environmentally compliant
Reg 57: Disposal Records — complete file; proceeds reconciliation; annual disposal report to PPDA

5. PPDA (PROCUREMENT PLANNING) REGULATIONS 2023:
Reg 58: Mandatory Annual Procurement Plan for all PDEs
Reg 59: Plan contents — description, method, estimated cost, source of funds, timeline
Reg 60: Contracts Committee approval by 30 September each year
Reg 61: Publication on PPDA website and notice board within 14 days of approval
Reg 62: Plan Amendments — Contracts Committee approval; reasons documented
Reg 63: Unplanned Procurement — only with Contracts Committee approval and emergency justification

6. PPDA (NEGOTIATIONS) REGULATIONS 2023:
Reg 64: When Negotiations Permitted — direct procurement; consultancy; restricted bidding with single responsive bid
Reg 65: Negotiations Committee — appointed by Contracts Committee; minimum 3 members
Reg 66: Negotiations Scope — technical, commercial, contractual terms; NEVER price in competitive methods
Reg 67: Negotiations Record — minutes signed; submitted to Contracts Committee for approval
Reg 68: Failed Negotiations — report to Contracts Committee; invite next-ranked firm or re-bid

7. RETAINED PPDA REGULATIONS 2014 (still applicable where not superseded):
- PPDA (Procuring and Disposing Entities Outside Uganda) Regulations 2014
- PPDA (Procurement of Medicines and Medical Supplies) Regulations 2014
- PPDA (Local Governments) Regulations 2006 (under review)

KEY COMPLIANCE AUDIT AREAS (2023 framework):
- Procurement plan approval and timely publication (Planning Regs 2023 Reg 58-63; Act S.36)
- Method selection vs current thresholds (Methods Regs 2023 Reg 12; Act S.26-33)
- Advertisement periods compliance (Methods Regs 2023 Reg 15; Act S.39)
- ESHS clause in ALL contracts (Methods Regs 2023 Reg 39) — NEW 2023 requirement
- Evaluation Committee composition and independence (PDE Regs 2023 Reg 5; Act S.18, S.42)
- Contracts Committee approvals and minutes (PDE Regs 2023 Reg 4; Act S.15)
- Standstill period 10 working days (Methods Regs 2023 Reg 28; Act S.44)
- Contract variations within 25% cap (Methods Regs 2023 Reg 32; Act S.58)
- Payment timeliness within 30 days (Methods Regs 2023 Reg 35; Act S.57)
- Advance payment authorisation — AG + PS/ST for above 20% (Methods Regs 2023 Reg 31)
- Conflict of interest declarations (PDE Regs 2023 Reg 6; Act S.18)
- Reservation scheme — 15% for Women/Youth/PWDs (PDE Regs 2023 Reg 10; Act S.31 amended)
- Disposal procedures (Disposal Regs 2023 Reg 50-57; Act S.64-67)
- Record keeping 10-year retention (Act S.95)
- Administrative review — 2 tiers only (Act S.90-91 as amended 2021)
- Technical minimum 75% for consultancy (Consultancy Regs 2023 Reg 44)
- GEPS platform reporting (PDE Regs 2023 Reg 7)`;

// ── REQUEST HANDLER ───────────────────────────────────────
async function handleRequest(req, res) {
  setCORS(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = req.url.split('?')[0];
  const db = loadDB();

  // Health check
  if (url === '/' || url === '/health') {
    return send(res, 200, {
      status: 'PPDA Audit Server running',
      version: '3.0',
      law: 'PPDA Act 2003 (as amended 2021) & PPDA Regulations 2023'
    });
  }

  // Login
  if (url === '/api/login' && req.method === 'POST') {
    const body = await readBody(req);
    const { username, password } = body;
    if (username === 'admin' && password === ADMIN_SECRET) {
      log(db, 'admin', 'LOGIN', 'Admin login'); saveDB(db);
      return send(res, 200, { ok:true, role:'admin', username:'admin', expiry:null });
    }
    const client = db.clients[username];
    if (!client || client.passwordHash !== hashPassword(password)) {
      log(db, username||'unknown', 'LOGIN_FAIL', 'Bad credentials'); saveDB(db);
      return send(res, 401, { ok:false, reason:'Incorrect username or password' });
    }
    const vr = valKey(client.key);
    if (!vr.ok) {
      log(db, username, 'LOGIN_DENIED', vr.reason); saveDB(db);
      return send(res, 403, { ok:false, reason:'Access denied: ' + vr.reason });
    }
    log(db, username, 'LOGIN', vr.daysLeft + ' days remaining'); saveDB(db);
    return send(res, 200, { ok:true, role:'client', username, expiry:vr.expiry, daysLeft:vr.daysLeft, entity:client.entity||'' });
  }

  // Extract findings
  if (url === '/api/extract' && req.method === 'POST') {
    const auth = authClient(req, db);
    if (!auth.ok) return send(res, 401, { error: auth.reason });
    const body = await readBody(req);
    const { evidence, meta } = body;
    if (!evidence || !evidence.length) return send(res, 400, { error: 'No evidence provided' });

    const combined = evidence.map(f => '--- FILE: ' + f.name + ' ---\n' + (f.text || '[No text]')).join('\n\n');

    const prompt = `You are a senior Uganda public procurement auditor with deep expertise in BOTH the PPDA Act 2003 (as amended 2021) AND the PPDA Regulations 2023 (effective 5th February 2024, comprising 7 regulation sets).

Entity: ${meta && meta.entity ? meta.entity : 'Not specified'}
Audit Period: ${meta && meta.period ? meta.period : 'Not specified'}

Extract ALL audit findings from the evidence. For each finding map it to the specific Act section AND the specific Regulation set and number from the PPDA Regulations 2023.

CRITICAL REQUIREMENTS:
- Always cite both instruments where applicable
- Flag ESHS compliance (Reg 39, Rules & Methods Regs 2023) — mandatory new 2023 requirement
- Check 2-tier admin review compliance (Act S.90-91 as amended 2021)
- Check reservation scheme for Women/Youth/PWDs (PDE Regs 2023 Reg 10)
- Apply revised thresholds (micro UGX 5M, restricted works up to UGX 1.5Bn)
- Note reduced bid periods (open domestic now 21 days minimum)
- Check consultancy technical minimum score of 75% (Consultancy Regs 2023 Reg 44)
- Set is_new_2023 to true for any finding related to a new 2023 Regulation requirement
- Do NOT limit findings — extract everything the evidence reveals including compliance observations

RESPOND ONLY with a valid JSON array. No explanation, no markdown fences. Example format:
[{
  "id": "F001",
  "title": "Short descriptive title",
  "observation": "Detailed factual observation from the evidence",
  "act_section": "Section X of the PPDA Act 2003 (as amended 2021)",
  "act_title": "Section name and subject",
  "reg_set": "Rules & Methods Regulations 2023",
  "reg_ref": "Regulation XX",
  "reg_title": "Regulation name and subject",
  "law_instrument": "Act or Regulations or Both",
  "violation": "Exactly how this violates or complies with the cited provisions",
  "risk": "High or Medium or Low",
  "implication": "Impact on public procurement integrity and value for money",
  "recommendation": "Specific corrective action citing the exact Act section and Regulation",
  "source_file": "filename where evidence was found",
  "is_new_2023": false
}]

LEGAL REFERENCE:
${PPDA_LAW}

EVIDENCE:
${combined.substring(0, 6000)}`;

    try {
      const result = await callAnthropic({ model:'claude-sonnet-4-20250514', max_tokens:4000, messages:[{ role:'user', content:prompt }] });
      if (result.error) return send(res, 500, { error: result.error.message });
      const raw = (result.content || []).map(b => b.text || '').join('');
      const clean = raw.replace(/```json|```/g, '').trim();
      const start = clean.indexOf('['), end = clean.lastIndexOf(']');
      if (start === -1 || end === -1) throw new Error('No JSON array found in AI response. Raw: ' + raw.substring(0,300));
      const findings = JSON.parse(clean.substring(start, end + 1));
      log(db, auth.username, 'EXTRACT', findings.length + ' findings'); saveDB(db);
      return send(res, 200, { ok:true, findings });
    } catch(e) {
      return send(res, 500, { error: e.message });
    }
  }

  // Generate report
  if (url === '/api/report' && req.method === 'POST') {
    const auth = authClient(req, db);
    if (!auth.ok) return send(res, 401, { error: auth.reason });
    const body = await readBody(req);
    const { findings, meta, template, reportType } = body;

    const DEFAULT_TPL = `PPDA PROCUREMENT COMPLIANCE AUDIT REPORT
=========================================
ENTITY: [Entity Name]
AUDIT TITLE: [Title]
AUDIT PERIOD: [Period]
LEAD AUDITOR: [Name and Designation]
DATE: [Date]
CLASSIFICATION: CONFIDENTIAL
LEGAL FRAMEWORK: PPDA Act 2003 (as amended 2021) and PPDA Regulations 2023 (effective 5 February 2024)

1. EXECUTIVE SUMMARY
2. BACKGROUND AND MANDATE
3. AUDIT SCOPE AND METHODOLOGY
4. SUMMARY OF FINDINGS TABLE (ID | Description | Act Reference | Regulation | Risk)
5. DETAILED FINDINGS (Criteria | Condition | Cause | Effect | Recommendation)
6. NEW 2023 REGULATION REQUIREMENTS FINDINGS
7. MANAGEMENT RESPONSE
8. OVERALL COMPLIANCE ASSESSMENT
9. RECOMMENDATIONS MATRIX
ANNEXES
  A. Evidence Schedule
  B. PPDA Act Provisions Referenced
  C. PPDA Regulations 2023 Provisions Referenced
  D. Audit Team Composition`;

    const tpl = template || DEFAULT_TPL;

    const prompt = `You are a senior Uganda government audit report writer with specialist expertise in the PPDA Act 2003 (as amended 2021) AND PPDA Regulations 2023 (effective 5th February 2024).

Generate a complete professional ${reportType || 'formal'} audit report.

METADATA:
Entity: ${meta && meta.entity ? meta.entity : '[Not specified]'}
Title: ${meta && meta.title ? meta.title : 'Procurement Compliance Audit'}
Period: ${meta && meta.period ? meta.period : '[Not specified]'}
Lead Auditor: ${meta && meta.auditor ? meta.auditor : '[Not specified]'}
Date: ${meta && meta.date ? meta.date : new Date().toLocaleDateString('en-UG')}

CRITICAL LEGAL CITATION RULES:
1. NEVER write "the law" generically — always state the specific provision
2. For Act: write "Section X of the PPDA Act 2003 (as amended 2021)"
3. For Regulations: write "Regulation X of the PPDA [specific set name] Regulations 2023"
4. Note where 2023 Regulations changed 2014 requirements
5. Highlight ESHS findings (Reg 39, Rules and Methods Regs 2023) as a NEW 2023 requirement
6. Highlight the 2-tier administrative review change (Act S.90-91 as amended 2021)

TEMPLATE — use as structural guide, include ALL warranted findings beyond this template:
${tpl}

FINDINGS (${findings ? findings.length : 0} total):
${JSON.stringify(findings || [], null, 2).substring(0, 5000)}

REPORT REQUIREMENTS:
1. Professional header with legal framework statement citing both the Act and all relevant Regulation sets
2. Executive Summary highlighting key findings with specific Act and Regulation references
3. Each finding in Criteria / Condition / Cause / Effect / Recommendation format
4. Criteria must state the exact Act section AND Regulation number and set name
5. Summary findings table with columns: ID | Finding | Act Reference | Regulation Reference | Risk
6. Separate section for findings relating to NEW 2023 Regulation requirements
7. Overall compliance rating with specific legal basis
8. Recommendations matrix prioritised High then Medium then Low
9. Annexes listing all Act sections referenced and all Regulation sets and numbers referenced

Write in formal audit English suitable for the Auditor General of Uganda and the PPDA Authority.`;

    try {
      const result = await callAnthropic({ model:'claude-sonnet-4-20250514', max_tokens:4000, messages:[{ role:'user', content:prompt }] });
      if (result.error) return send(res, 500, { error: result.error.message });
      const text = (result.content || []).map(b => b.text || '').join('');
      log(db, auth.username, 'REPORT', (reportType || 'formal') + ' report generated'); saveDB(db);
      return send(res, 200, { ok:true, report:text });
    } catch(e) {
      return send(res, 500, { error: e.message });
    }
  }

  // Admin — create client
  if (url === '/api/admin/client' && req.method === 'POST') {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return send(res, 403, { error:'Unauthorized' });
    const body = await readBody(req);
    const { username, password, key, entity, notes } = body;
    if (!username || !password || !key) return send(res, 400, { error:'username, password and key required' });
    const vr = valKey(key);
    if (!vr.ok) return send(res, 400, { error:'Invalid key: ' + vr.reason });
    db.clients[username] = { passwordHash:hashPassword(password), key, entity:entity||'', notes:notes||'', created:new Date().toISOString(), expiry:new Date(vr.expiry).toISOString() };
    log(db, 'admin', 'CREATE_CLIENT', username + ' | ' + vr.daysLeft + ' days'); saveDB(db);
    return send(res, 200, { ok:true, username, daysLeft:vr.daysLeft, expiry:new Date(vr.expiry).toLocaleDateString() });
  }

  // Admin — list clients
  if (url === '/api/admin/clients' && req.method === 'GET') {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return send(res, 403, { error:'Unauthorized' });
    const list = Object.entries(db.clients).map(([u, d]) => {
      const vr = valKey(d.key);
      return { username:u, entity:d.entity, notes:d.notes, created:d.created, expiry:d.expiry, active:vr.ok, daysLeft:vr.ok ? vr.daysLeft : 0 };
    });
    return send(res, 200, { ok:true, clients:list });
  }

  // Admin — delete client
  if (url.startsWith('/api/admin/client/') && req.method === 'DELETE') {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return send(res, 403, { error:'Unauthorized' });
    const username = url.split('/').pop();
    if (!db.clients[username]) return send(res, 404, { error:'Client not found' });
    delete db.clients[username];
    log(db, 'admin', 'DELETE_CLIENT', username); saveDB(db);
    return send(res, 200, { ok:true });
  }

  // Admin — generate key
  if (url === '/api/admin/genkey' && req.method === 'POST') {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return send(res, 403, { error:'Unauthorized' });
    const body = await readBody(req);
    const { days, clientId } = body;
    if (!days || days < 1) return send(res, 400, { error:'Invalid duration' });
    const key = genKey(parseInt(days), clientId || 'client');
    const expiry = new Date(Date.now() + days * 86400000);
    log(db, 'admin', 'GENKEY', (clientId||'client') + ' | ' + days + 'd'); saveDB(db);
    return send(res, 200, { ok:true, key, expiry:expiry.toLocaleDateString(), daysLeft:parseInt(days) });
  }

  // Admin — validate key
  if (url === '/api/admin/valkey' && req.method === 'POST') {
    const body = await readBody(req);
    return send(res, 200, valKey(body.key || ''));
  }

  // Admin — activity logs
  if (url === '/api/admin/logs' && req.method === 'GET') {
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return send(res, 403, { error:'Unauthorized' });
    return send(res, 200, { ok:true, logs:db.logs.slice(0, 100) });
  }

  // Change password
  if (url === '/api/changepwd' && req.method === 'POST') {
    const auth = authClient(req, db);
    if (!auth.ok) return send(res, 401, { error:auth.reason });
    const body = await readBody(req);
    const { oldPassword, newPassword } = body;
    const client = db.clients[auth.username];
    if (!client) return send(res, 404, { error:'User not found' });
    if (client.passwordHash !== hashPassword(oldPassword)) return send(res, 400, { error:'Current password incorrect' });
    if (!newPassword || newPassword.length < 6) return send(res, 400, { error:'New password too short (minimum 6 characters)' });
    client.passwordHash = hashPassword(newPassword);
    log(db, auth.username, 'CHANGE_PWD', 'Password updated'); saveDB(db);
    return send(res, 200, { ok:true });
  }

  return send(res, 404, { error:'Route not found: ' + url });
}

// ── START ─────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch(e) {
    setCORS(res);
    send(res, 500, { error:'Server error: ' + e.message });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('PPDA Audit Server running on port ' + PORT);
  console.log('Legal framework: PPDA Act 2003 (as amended 2021) & PPDA Regulations 2023');
  console.log('Health check: /health');
  if (!ANTHROPIC_API_KEY) {
    console.warn('WARNING: ANTHROPIC_API_KEY not set — AI features will not work');
  }
});
