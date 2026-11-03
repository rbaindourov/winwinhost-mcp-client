# `@winwinhost/mcp-agent-client` — Multi-Domain MCP & x402 SDK

Zero-dependency Node.js 18+ client adapter, and Model Context Protocol (MCP) configuration generator for the **WinWinHost 101-Domain Agentic Network**.

---

## 🌐 Live API & MCP Documentation Directory

Every production microservice in the WinWinHost & MultiDomainCMS ecosystem publishes machine-readable discovery manifests (`/.well-known/mcp/server.json`, `/.well-known/agent-card.json`, `/.well-known/x402.json`, `/llms.txt`) and comprehensive human/agent reference guides:

| Service Hub | Primary Capability | Live Documentation URL |
| :--- | :--- | :--- |
| **WinWinHost Unified MCP Gateway** | 14+ MCP Tools (`SSE` & JSON-RPC), RBAC Scopes, Prometheus/Loki Telemetry & Affiliate Campaigns | [`https://winwinhost.com/mcp-documentation`](https://winwinhost.com/mcp-documentation) |
| **101-Domain Single-Process SSR Benchmark** | Live Prometheus RAM (`2.3 GB` vs. `40.4 GB` cPanel), TTFB (`14 ms`) | [`https://winwinhost.com/benchmark`](https://winwinhost.com/benchmark) |
| **ArticleSyndicator Pay-Per-Post & x402** | 93-Domain Permanent Article Syndication (`$1.00 USDC` on Base L2 Chain ID `8453` or PayPal/Card) | [`https://articlesyndicator.net/mcp-pay-per-post-syndication-api`](https://articlesyndicator.net/mcp-pay-per-post-syndication-api) |
| **FreeInvoicer Zero-Auth Agent Invoicing** | Instant US-Letter HTML & Vector PDF Invoice Generation + Email Dispatch (`$0`, No API Key Required) | [`https://freeinvoicer.com/mcp-agent-invoicing`](https://freeinvoicer.com/mcp-agent-invoicing) |
| **WebDesigner.la Design Audit & Preview API** | Topological PageRank (`UR 1-100`), WCAG 2.1 AA / CWV Audit (`$0.05 USDC`) & White-Label `/preview` | [`https://webdesigner.la/mcp-design-audit-and-lead-api`](https://webdesigner.la/mcp-design-audit-and-lead-api) |
| **DigitalSpying Ghidra & REA Binary Forensics** | NSA Ghidra `12.1.4` + REA MCP (`61` Tools) ELF/PE/Mach-O/APK/Wasm Triage & Clean-Room C/Rust Ports | [`https://digitalspying.com/ghidra-mcp-reverse-engineering-api-docs`](https://digitalspying.com/ghidra-mcp-reverse-engineering-api-docs) |
| **LinkDepot Curated Directory Citations** | Permanent `rel="dofollow"` Contextual Directory Listings Across 12 Thematic Silos (`$9.99/mo`) | [`https://linkdepot.net/mcp-directory-citation-api`](https://linkdepot.net/mcp-directory-citation-api) |
| **LeadSuperstore Ping-Tree Lead Exchange** | Exclusive Geo-Targeted SMB, Legal, Financial & Home-Service Lead Batches (`$0.25 USDC` / `50/50` Rev-Share) | [`https://leadsuperstore.net/mcp-lead-exchange-ping-tree-api`](https://leadsuperstore.net/mcp-lead-exchange-ping-tree-api) |
| **ContactCampaigns CAN-SPAM Outreach API** | Svix HMAC Resend Webhooks, MX/SMTP Pre-Flight Scrubbing & Autonomous Multi-Touch Sequences | [`https://contactcampaigns.com/mcp-outreach-campaign-automation-api`](https://contactcampaigns.com/mcp-outreach-campaign-automation-api) |
| **AffiliatePartners Attribution & Ping-Tree** | Multi-Vertical Click/Impression/Lead Tracking & 27-Domain Financial Ping-Tree Waterfall | [`https://affiliatepartners.biz/api-docs`](https://affiliatepartners.biz/api-docs) |

---

## ⚡ Quickstart

### 1. Download Ready-to-Use MCP Client Configs (Claude Desktop, Cursor, VS Code)

```bash
# Claude Desktop (claude_desktop_config.json)
curl -sS https://winwinhost.com/api/mcp/client-config/claude_desktop_config.json > claude_desktop_config.json

# Cursor IDE (.cursor/mcp.json)
curl -sS https://winwinhost.com/api/mcp/client-config/cursor_mcp.json > .cursor/mcp.json

# VS Code / GitHub Copilot (.vscode/mcp.json)
curl -sS https://winwinhost.com/api/mcp/client-config/vscode_mcp.json > .vscode/mcp.json
```

### 2. Zero-Auth Agent Invoicing (`FreeInvoicer.com`)

```javascript
const { WinWinHostMcpClient } = require('@winwinhost/mcp-agent-client');

const client = new WinWinHostMcpClient();
const receipt = await client.createFreeInvoice({
  businessName: 'Autonomous Coding Agent',
  clientName: 'Acme Corp',
  clientEmail: 'billing@acme.example.com',
  items: [{ description: 'Clean-Room Wasm Port & Security Audit', quantity: 1, unitPrice: 450 }],
  sendEmail: true
});
console.log(receipt.shareableInvoiceUrl, receipt.pdfDownloadUrl);
```

### 3. Cryptographic `GitHubSyncProof` & Dual-Origin CMS Upsert

Workstation and third-party agents that commit and push `data/posts/<domain>/` shards to GitHub before calling the live CMS API can generate a signed `GitHubSyncProof` (using either a per-agent `ag_prf_*` proof secret or `CMS_SYNC_PROOF_SECRET`) so the production server verifies the proof and skips duplicate server-side Git commits:

```javascript
const {
  WinWinHostMcpClient,
  createGitHubSyncProof,
  encodeGitHubSyncProofHeader,
  verifyGitHubSyncProof
} = require('@winwinhost/mcp-agent-client');

const client = new WinWinHostMcpClient({
  baseUrl: 'https://winwinhost.com',
  apiKey: process.env.CMS_API_KEY,               // ag_sec_*
  syncProofSecret: process.env.CMS_PROOF_SECRET, // ag_prf_* (or cluster HMAC secret)
  agentId: 'agents@webdesigner',
  conversationId: 'e2366a24-ad8e-43e5-a775-86e17c755719'
});

// Option A: Automatically compute and attach X-GitHub-Sync-Proof header + githubSyncProof body
const result = await client.upsertPost({
  domain: 'winwinhost.com',
  slug: 'zero-trust-edge-routing',
  title: 'Zero-Trust Edge Routing Architecture',
  content: '<p>Full technical breakdown...</p>',
  syncProofOptions: {
    commitSha: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    branch: 'main'
  }
});

// Option B: Standalone proof generation & verification
const proof = createGitHubSyncProof({
  domain: 'winwinhost.com',
  slug: 'zero-trust-edge-routing',
  postContent: '<p>Full technical breakdown...</p>',
  postModified: '2026-10-18T12:00:00.000Z',
  commitSha: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  secret: process.env.CMS_PROOF_SECRET
});
const headerValue = encodeGitHubSyncProofHeader(proof);
const check = verifyGitHubSyncProof(headerValue, {
  domain: 'winwinhost.com',
  slug: 'zero-trust-edge-routing',
  postContent: '<p>Full technical breakdown...</p>',
  postModified: '2026-10-18T12:00:00.000Z',
  secret: process.env.CMS_PROOF_SECRET
});
console.log(check.valid, check.keyScope);
```

