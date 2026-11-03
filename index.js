'use strict';

/**
 * @winwinhost/mcp-agent-client
 * Zero-dependency SDK for the WinWinHost 101-Domain Agentic Network.
 *
 * Official Documentation Directory:
 * - Master MCP & A2A Gateway:       https://winwinhost.com/mcp-documentation
 * - 101-Domain SSR Benchmark:       https://winwinhost.com/benchmark
 * - Pay-Per-Post & x402 Publishing: https://articlesyndicator.net/mcp-pay-per-post-syndication-api
 * - Zero-Auth Agent Invoicing:      https://freeinvoicer.com/mcp-agent-invoicing
 * - Design Audit & Preview Sandbox: https://webdesigner.la/mcp-design-audit-and-lead-api
 * - Ghidra & REA Binary Forensics:  https://digitalspying.com/ghidra-mcp-reverse-engineering-api-docs
 * - LinkDepot Directory Citations:  https://linkdepot.net/mcp-directory-citation-api
 * - LeadSuperstore Ping-Tree API:   https://leadsuperstore.net/mcp-lead-exchange-ping-tree-api
 * - ContactCampaigns Outreach API:  https://contactcampaigns.com/mcp-outreach-campaign-automation-api
 * - AffiliatePartners Attribution:  https://affiliatepartners.biz/api-docs
 */

const DOCUMENTATION_HUB_URLS = Object.freeze({
  masterGateway: 'https://winwinhost.com/mcp-documentation',
  benchmarkDashboard: 'https://winwinhost.com/benchmark',
  articleSyndicatorPayPerPost: 'https://articlesyndicator.net/mcp-pay-per-post-syndication-api',
  freeInvoicerZeroAuthMcp: 'https://freeinvoicer.com/mcp-agent-invoicing',
  webdesignerLaDesignAudit: 'https://webdesigner.la/mcp-design-audit-and-lead-api',
  digitalSpyingGhidraForensics: 'https://digitalspying.com/ghidra-mcp-reverse-engineering-api-docs',
  linkDepotDirectoryCitations: 'https://linkdepot.net/mcp-directory-citation-api',
  leadSuperstorePingTree: 'https://leadsuperstore.net/mcp-lead-exchange-ping-tree-api',
  contactCampaignsOutreach: 'https://contactcampaigns.com/mcp-outreach-campaign-automation-api',
  affiliatePartnersAttribution: 'https://affiliatepartners.biz/api-docs'
});

const BENCHMARK_SAMPLE_DOMAINS = Object.freeze([
  'winwinhost.com',
  'webdesigner.la',
  'articlesyndicator.net',
  'freeinvoicer.com',
  'digitalspying.com',
  'linkdepot.net',
  'leadsuperstore.net',
  'contactcampaigns.com',
  'financequickly.com',
  'vannuyslegal.com'
]);

const crypto = require('crypto');
const os = require('os');
const { execFileSync } = require('child_process');

const DEFAULT_SYNC_PROOF_SECRET = 'cms-default-sync-proof-hmac-key-2026';
const PROOF_TIMESTAMP_TOLERANCE_MS = 15 * 60 * 1000;

function cleanSdkDomain(domainInput) {
  if (!domainInput) return '';
  return String(domainInput)
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, '')
    .replace(/^www\./i, '')
    .replace(/\/.*$/, '');
}

function slugifySdkTitle(titleInput) {
  return String(titleInput || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

/**
 * Computes deterministic SHA-256 hex digest over domain, slug, postContent, and postModified.
 */
function computeContentSha256(domainOrObj, slug, postContent = '', postModified = '') {
  if (domainOrObj && typeof domainOrObj === 'object' && !Array.isArray(domainOrObj)) {
    const obj = domainOrObj;
    const cDomain = cleanSdkDomain(obj.domain || '');
    const cSlug = String(obj.slug || obj.postName || obj.post_name || '').trim();
    const content = String(obj.postContent ?? obj.post_content ?? '');
    const rawMod = obj.postModified ?? obj.post_modified ?? '';
    const mod = rawMod instanceof Date ? rawMod.toISOString() : String(rawMod ?? '');
    return crypto
      .createHash('sha256')
      .update(`${cDomain}:${cSlug}:${content}:${mod}`, 'utf8')
      .digest('hex');
  }
  const cDomain = cleanSdkDomain(domainOrObj);
  const cSlug = String(slug || '').trim();
  const content = String(postContent ?? '');
  const mod = postModified instanceof Date ? postModified.toISOString() : String(postModified ?? '');
  return crypto
    .createHash('sha256')
    .update(`${cDomain}:${cSlug}:${content}:${mod}`, 'utf8')
    .digest('hex');
}

/**
 * Deterministically derives or returns a scoped per-agent `syncProofSecret` (`ag_prf_<32-hex-chars>`)
 * from an author record or raw API key.
 */
function deriveAgentSyncProofSecret(authorRecordOrKey, optionalUsername) {
  if (!authorRecordOrKey) return '';
  if (typeof authorRecordOrKey === 'object') {
    if (
      typeof authorRecordOrKey.syncProofSecret === 'string' &&
      authorRecordOrKey.syncProofSecret.trim()
    ) {
      return authorRecordOrKey.syncProofSecret.trim();
    }
    const seed = String(authorRecordOrKey.apiKey || authorRecordOrKey.apiKeyHash || '').trim();
    if (!seed) return '';
    const uname = String(authorRecordOrKey.username || optionalUsername || '')
      .trim()
      .toLowerCase()
      .replace(/^agents@/, '');
    const digest = crypto
      .createHmac('sha256', 'cms-agent-scoped-sync-proof-kdf-v1')
      .update(`${uname}:${seed}`, 'utf8')
      .digest('hex')
      .slice(0, 32);
    return `ag_prf_${digest}`;
  }
  if (typeof authorRecordOrKey === 'string' && authorRecordOrKey.trim()) {
    const trimmed = authorRecordOrKey.trim();
    if (trimmed.startsWith('ag_prf_')) return trimmed;
    if (optionalUsername && String(optionalUsername).trim()) {
      const uname = String(optionalUsername)
        .trim()
        .toLowerCase()
        .replace(/^agents@/, '');
      const digest = crypto
        .createHmac('sha256', 'cms-agent-scoped-sync-proof-kdf-v1')
        .update(`${uname}:${trimmed}`, 'utf8')
        .digest('hex')
        .slice(0, 32);
      return `ag_prf_${digest}`;
    }
    const digest = crypto
      .createHmac('sha256', 'cms-agent-scoped-sync-proof-kdf-v1')
      .update(trimmed, 'utf8')
      .digest('hex')
      .slice(0, 32);
    return `ag_prf_${digest}`;
  }
  return '';
}

function computeProofSignature(fields, secret) {
  const hmacSecret = secret || process.env.CMS_SYNC_PROOF_SECRET || DEFAULT_SYNC_PROOF_SECRET;
  const cDomain = cleanSdkDomain(fields.domain);
  const cSlug = String(fields.slug || fields.postName || fields.post_name || '').trim();
  const signingInput = [
    String(fields.commitSha || ''),
    String(fields.branch || ''),
    cDomain,
    cSlug,
    String(fields.contentSha256 || ''),
    String(fields.agentId || ''),
    String(fields.conversationId || ''),
    String(fields.timestamp ?? '')
  ].join(':');

  return crypto
    .createHmac('sha256', hmacSecret)
    .update(signingInput, 'utf8')
    .digest('hex');
}

function resolveHeadCommitSha(cwd) {
  try {
    const out = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: cwd || process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000
    }).trim();
    if (/^[0-9a-f]{40}$/i.test(out)) {
      return out.toLowerCase();
    }
  } catch (_) {}
  return '0'.repeat(40);
}

/**
 * Creates a signed GitHubSyncProof object for a domain post mutation.
 */
function createGitHubSyncProof(params = {}) {
  const cDomain = cleanSdkDomain(params.domain);
  const slug = String(
    params.slug || params.postName || params.post_name || slugifySdkTitle(params.postTitle) || ''
  ).trim();
  const commitSha =
    params.commitSha && /^[0-9a-f]{40}$/i.test(String(params.commitSha).trim())
      ? String(params.commitSha).trim().toLowerCase()
      : resolveHeadCommitSha(params.cwd);
  const branch = String(params.branch || 'main').trim();
  const agentId = String(
    params.agentId || process.env.CMS_AGENT_ID || `agents@${os.hostname()}`
  ).trim();
  const conversationId = String(
    params.conversationId || process.env.CMS_CONVERSATION_ID || 'local-workstation-sync'
  ).trim();
  let timestamp = Date.now();
  if (typeof params.timestamp === 'number' && Number.isFinite(params.timestamp)) {
    timestamp = params.timestamp;
  } else if (typeof params.timestamp === 'string' && params.timestamp.trim()) {
    const parsedTs = Date.parse(params.timestamp.trim());
    if (Number.isFinite(parsedTs)) {
      timestamp = parsedTs;
    }
  }
  const contentSha256 = params.contentSha256
    ? String(params.contentSha256).trim().toLowerCase()
    : computeContentSha256(
        cDomain,
        slug,
        params.postContent ?? params.post_content ?? '',
        params.postModified ?? params.post_modified ?? ''
      );

  const signature = computeProofSignature(
    {
      commitSha,
      branch,
      domain: cDomain,
      slug,
      contentSha256,
      agentId,
      conversationId,
      timestamp
    },
    params.secret
  );

  return {
    commitSha,
    branch,
    domain: cDomain,
    slug,
    contentSha256,
    agentId,
    conversationId,
    timestamp,
    signature
  };
}

/**
 * Encodes a GitHubSyncProof as Base64 for the `X-GitHub-Sync-Proof` HTTP header.
 */
function encodeGitHubSyncProofHeader(proof) {
  return Buffer.from(JSON.stringify(proof), 'utf8').toString('base64');
}

/**
 * Parses a GitHubSyncProof from an object, JSON string, or Base64-encoded string.
 */
function parseGitHubSyncProof(input) {
  if (!input) return null;
  if (typeof input === 'object' && !Array.isArray(input)) {
    return input;
  }
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) return null;
    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return parsed;
        }
      } catch (_) {
        return null;
      }
    }
    try {
      const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
      const parsed = JSON.parse(decoded);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (_) {
      return null;
    }
  }
  return null;
}

function buildSdkCandidateSecrets(proof, expected = {}) {
  const candidates = [];
  const seen = new Set();

  const addCandidate = (secret, scope) => {
    if (!secret || typeof secret !== 'string') return;
    const trimmed = secret.trim();
    if (!trimmed || seen.has(trimmed)) return;
    seen.add(trimmed);
    candidates.push({ secret: trimmed, scope });
  };

  if (expected.secret) {
    const isAgentScoped =
      expected.keyScope === 'agent_scoped_secret' ||
      String(expected.secret).trim().startsWith('ag_prf_') ||
      String(expected.secret).trim().startsWith('ag_sec_');
    addCandidate(
      String(expected.secret),
      isAgentScoped ? 'agent_scoped_secret' : 'cluster_secret'
    );
  }

  addCandidate(
    process.env.CMS_SYNC_PROOF_SECRET || DEFAULT_SYNC_PROOF_SECRET,
    'cluster_secret'
  );

  const rawAgentId = String(proof?.agentId || '').trim().toLowerCase();
  const strippedAgentId = rawAgentId.replace(/^agents@/, '');
  const attributedUsername = String(expected.attributedAuthor?.username || '')
    .trim()
    .toLowerCase()
    .replace(/^agents@/, '');
  const expectedAuthor = String(attributedUsername || expected.author || '')
    .trim()
    .toLowerCase()
    .replace(/^agents@/, '');

  if (Array.isArray(expected.agentSecrets)) {
    for (const s of expected.agentSecrets) {
      addCandidate(s, 'agent_scoped_secret');
      addCandidate(deriveAgentSyncProofSecret(s, expectedAuthor || strippedAgentId), 'agent_scoped_secret');
      addCandidate(deriveAgentSyncProofSecret(s), 'agent_scoped_secret');
    }
  } else if (typeof expected.agentSecrets === 'string') {
    addCandidate(expected.agentSecrets, 'agent_scoped_secret');
    addCandidate(deriveAgentSyncProofSecret(expected.agentSecrets, expectedAuthor || strippedAgentId), 'agent_scoped_secret');
    addCandidate(deriveAgentSyncProofSecret(expected.agentSecrets), 'agent_scoped_secret');
  }

  if (expected.attributedAuthor && typeof expected.attributedAuthor === 'object') {
    if (expected.attributedAuthor.syncProofSecret) {
      addCandidate(expected.attributedAuthor.syncProofSecret, 'agent_scoped_secret');
    }
    if (expected.attributedAuthor.apiKey) {
      addCandidate(deriveAgentSyncProofSecret(expected.attributedAuthor), 'agent_scoped_secret');
      addCandidate(expected.attributedAuthor.apiKey, 'agent_scoped_secret');
    }
  }

  try {
    const fs = require('fs');
    const path = require('path');
    const usersPath =
      process.env.CMS_USERS_PATH || path.resolve(__dirname, '../../data/users.json');
    if (fs.existsSync(usersPath)) {
      const users = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
      if (Array.isArray(users)) {
        const matchingUsers = [];
        for (const u of users) {
          if (!u || u.isActive === false) continue;
          const uname = String(u.username || '').trim().toLowerCase();
          const strippedUname = uname.replace(/^agents@/, '');
          const uid = String(u._id || u.id || '').trim().toLowerCase();
          const uAuthorId = String(u.authorId || '').trim().toLowerCase();
          const candidateIds = [uname, strippedUname, uid, uAuthorId].filter(Boolean);
          if (candidateIds.length === 0) continue;

          if (attributedUsername) {
            if (candidateIds.includes(attributedUsername)) {
              matchingUsers.push(u);
            }
          } else if (
            (rawAgentId && candidateIds.includes(rawAgentId)) ||
            (strippedAgentId && candidateIds.includes(strippedAgentId)) ||
            (expectedAuthor && candidateIds.includes(expectedAuthor))
          ) {
            matchingUsers.push(u);
          }
        }

        for (const u of matchingUsers) {
          if (u.syncProofSecret) {
            addCandidate(u.syncProofSecret, 'agent_scoped_secret');
          }
          const derived = deriveAgentSyncProofSecret(u);
          if (derived) {
            addCandidate(derived, 'agent_scoped_secret');
          }
          if (u.apiKey) {
            addCandidate(u.apiKey, 'agent_scoped_secret');
            addCandidate(deriveAgentSyncProofSecret(u.apiKey), 'agent_scoped_secret');
          }
        }
      }
    }
  } catch (_) {}

  return candidates;
}

/**
 * Verifies a GitHubSyncProof against expected domain, slug, content, timestamp freshness, and HMAC signature.
 */
function verifyGitHubSyncProof(proofInput, expected = {}) {
  const proof = parseGitHubSyncProof(proofInput);
  if (!proof || typeof proof !== 'object') {
    return { valid: false, reason: 'Malformed or missing GitHubSyncProof payload' };
  }

  const requiredFields = [
    'commitSha',
    'branch',
    'domain',
    'slug',
    'contentSha256',
    'agentId',
    'conversationId',
    'timestamp',
    'signature'
  ];

  for (const field of requiredFields) {
    if (proof[field] === undefined || proof[field] === null || proof[field] === '') {
      return { valid: false, reason: `Missing required proof field: ${field}` };
    }
  }

  const commitSha = String(proof.commitSha).trim();
  if (!/^[0-9a-f]{40}$/i.test(commitSha)) {
    return { valid: false, reason: 'Invalid commitSha: must be a 40-character hexadecimal Git SHA' };
  }

  const expectedBranch = expected.branch || 'main';
  if (String(proof.branch).trim() !== expectedBranch) {
    return {
      valid: false,
      reason: `Invalid branch "${proof.branch}": expected "${expectedBranch}"`
    };
  }

  const now = typeof expected.now === 'number' ? expected.now : Date.now();
  const toleranceMs =
    typeof expected.toleranceMs === 'number' ? expected.toleranceMs : PROOF_TIMESTAMP_TOLERANCE_MS;
  const ts = Number(proof.timestamp);
  if (typeof proof.timestamp !== 'number' || !Number.isFinite(ts) || Math.abs(now - ts) > toleranceMs) {
    return {
      valid: false,
      reason: 'Proof timestamp is expired or outside the ±15 minute freshness window'
    };
  }

  const proofDomain = cleanSdkDomain(proof.domain);
  if (expected.domain && proofDomain !== cleanSdkDomain(expected.domain)) {
    return {
      valid: false,
      reason: `Domain mismatch: proof domain "${proofDomain}" does not match expected "${cleanSdkDomain(expected.domain)}"`
    };
  }

  const proofSlug = String(proof.slug || proof.postName || proof.post_name || '').trim();
  const expectedSlug = expected.slug || expected.postName || expected.post_name;
  if (expectedSlug && proofSlug !== String(expectedSlug).trim()) {
    return {
      valid: false,
      reason: `Slug mismatch: proof slug "${proofSlug}" does not match expected "${String(expectedSlug).trim()}"`
    };
  }

  const proofContentSha = String(proof.contentSha256).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(proofContentSha)) {
    return { valid: false, reason: 'Invalid contentSha256 format' };
  }

  const candidateSecrets = buildSdkCandidateSecrets(proof, expected);
  const providedSigBuf = Buffer.from(String(proof.signature), 'utf8');
  let signatureValid = false;
  let matchedKeyScope = 'cluster_secret';

  for (const cand of candidateSecrets) {
    const expectedSig = computeProofSignature(
      {
        commitSha: String(proof.commitSha),
        branch: String(proof.branch),
        domain: proofDomain,
        slug: proofSlug,
        contentSha256: String(proof.contentSha256),
        agentId: String(proof.agentId),
        conversationId: String(proof.conversationId),
        timestamp: proof.timestamp
      },
      cand.secret
    );
    const expectedSigBuf = Buffer.from(expectedSig, 'utf8');
    if (
      providedSigBuf.length === expectedSigBuf.length &&
      crypto.timingSafeEqual(providedSigBuf, expectedSigBuf)
    ) {
      signatureValid = true;
      matchedKeyScope = cand.scope;
      break;
    }
  }

  if (expected.postContent !== undefined) {
    const primaryExpectedSha = computeContentSha256(
      proofDomain,
      proofSlug,
      expected.postContent,
      expected.postModified ?? ''
    );
    const emptyModSha = computeContentSha256(proofDomain, proofSlug, expected.postContent, '');
    const rawContentSha =
      expected.rawPostContent !== undefined
        ? computeContentSha256(
            proofDomain,
            proofSlug,
            expected.rawPostContent,
            expected.postModified ?? ''
          )
        : null;
    const rawContentEmptyModSha =
      expected.rawPostContent !== undefined
        ? computeContentSha256(proofDomain, proofSlug, expected.rawPostContent, '')
        : null;
    const existingModSha =
      expected.existingPostModified !== undefined
        ? computeContentSha256(
            proofDomain,
            proofSlug,
            expected.postContent,
            expected.existingPostModified ?? ''
          )
        : null;
    const rawExistingModSha =
      expected.rawPostContent !== undefined && expected.existingPostModified !== undefined
        ? computeContentSha256(
            proofDomain,
            proofSlug,
            expected.rawPostContent,
            expected.existingPostModified ?? ''
          )
        : null;

    const contentMatches =
      proofContentSha === primaryExpectedSha ||
      (Boolean(expected.allowEmptyPostModifiedFallback) &&
        (proofContentSha === emptyModSha ||
          proofContentSha === rawContentSha ||
          proofContentSha === rawContentEmptyModSha ||
          (existingModSha !== null && proofContentSha === existingModSha) ||
          (rawExistingModSha !== null && proofContentSha === rawExistingModSha)));

    if (!contentMatches) {
      return {
        valid: false,
        reason: 'contentSha256 mismatch: post content or post_modified does not match proof digest'
      };
    }
  }

  if (!signatureValid) {
    return { valid: false, reason: 'HMAC-SHA256 signature verification failed' };
  }

  return {
    valid: true,
    reason: 'verified',
    keyScope: matchedKeyScope,
    commitSha: commitSha.toLowerCase(),
    branch: String(proof.branch),
    domain: proofDomain,
    slug: proofSlug,
    contentSha256: proofContentSha,
    agentId: String(proof.agentId),
    conversationId: String(proof.conversationId),
    timestamp: proof.timestamp
  };
}

class WinWinHostMcpClient {
  /**
   * @param {object} [options]
   * @param {string} [options.baseUrl] Default: 'https://winwinhost.com'
   * @param {string} [options.apiKey] Optional ag_sec_* Bearer token for authenticated tools
   * @param {string} [options.syncProofSecret] Optional ag_prf_* or HMAC secret for signing GitHubSyncProofs
   * @param {string} [options.agentId] Optional default agent identity (e.g. 'agents@webdesigner')
   * @param {string} [options.conversationId] Optional default Conversation-ID trailer
   * @param {string} [options.affiliateRef] Optional affiliate_ref for 50% recurring attribution
   * @param {typeof fetch} [options.fetchImpl] Custom fetch implementation (for testing)
   */
  constructor(options = {}) {
    this.baseUrl = String(options.baseUrl || 'https://winwinhost.com').replace(/\/+$/, '');
    this.apiKey = options.apiKey ? String(options.apiKey).trim() : '';
    this.syncProofSecret = options.syncProofSecret ? String(options.syncProofSecret).trim() : '';
    this.agentId = options.agentId ? String(options.agentId).trim() : '';
    this.conversationId = options.conversationId ? String(options.conversationId).trim() : '';
    this.affiliateRef = options.affiliateRef ? String(options.affiliateRef).trim() : '';
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
  }

  _headers(extra = {}) {
    const h = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...extra
    };
    if (this.apiKey) {
      h.Authorization = `Bearer ${this.apiKey}`;
    }
    return h;
  }

  _resolveSyncProofAttachment(params = {}) {
    const rawProof = params.githubSyncProof;
    const syncOpts = params.syncProofOptions;
    if (!rawProof && !syncOpts) {
      return null;
    }

    if (rawProof) {
      const parsed = parseGitHubSyncProof(rawProof);
      const headerValue =
        typeof rawProof === 'string' && !rawProof.trim().startsWith('{')
          ? rawProof.trim()
          : encodeGitHubSyncProofHeader(parsed || rawProof);
      return {
        proof: parsed || rawProof,
        headerValue
      };
    }

    const postObj = params.post || params;
    const domain = cleanSdkDomain(params.domain || params.targetDomain || postObj.domain || '');
    const postTitle = String(
      postObj.post_title || postObj.title || postObj.postTitle || params.title || params.post_title || ''
    ).trim();
    const slug = String(
      postObj.post_name ||
        postObj.slug ||
        postObj.postName ||
        params.slug ||
        params.post_name ||
        params.postName ||
        slugifySdkTitle(postTitle) ||
        ''
    ).trim();
    const postContent = String(
      postObj.post_content ?? postObj.content ?? postObj.postContent ?? params.content ?? params.post_content ?? ''
    );
    const postModified =
      postObj.post_modified ?? postObj.postModified ?? params.post_modified ?? params.postModified ?? '';

    const proof = createGitHubSyncProof({
      domain,
      slug,
      postTitle,
      postContent,
      postModified,
      commitSha: syncOpts.commitSha,
      branch: syncOpts.branch || 'main',
      agentId: syncOpts.agentId || this.agentId || undefined,
      conversationId: syncOpts.conversationId || this.conversationId || undefined,
      secret: syncOpts.secret || this.syncProofSecret || undefined,
      timestamp: syncOpts.timestamp,
      cwd: syncOpts.cwd
    });

    return {
      proof,
      headerValue: encodeGitHubSyncProofHeader(proof)
    };
  }

  async discoverMcpManifest(domainOrBaseUrl) {
    const base = domainOrBaseUrl
      ? String(domainOrBaseUrl).startsWith('http')
        ? String(domainOrBaseUrl).replace(/\/+$/, '')
        : `https://${domainOrBaseUrl}`
      : this.baseUrl;
    const res = await this.fetchImpl(`${base}/.well-known/mcp/server.json`, {
      method: 'GET',
      headers: this._headers()
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch MCP manifest from ${base}: HTTP ${res.status}`);
    }
    return res.json();
  }

  async getClientConfig(target = 'claude_desktop_config.json') {
    const res = await this.fetchImpl(
      `${this.baseUrl}/api/a2a/mcp/client-config/${encodeURIComponent(target)}`,
      {
        method: 'GET',
        headers: this._headers()
      }
    );
    if (!res.ok) {
      throw new Error(`Failed to fetch client config (${target}): HTTP ${res.status}`);
    }
    return res.json();
  }

  /**
   * Upserts a post via POST /api/cms/posts/upsert, automatically attaching X-GitHub-Sync-Proof
   * and githubSyncProof when githubSyncProof or syncProofOptions is provided.
   */
  async upsertPost(payload = {}) {
    const domain = cleanSdkDomain(
      payload.domain || payload.targetDomain || (payload.post && payload.post.domain) || ''
    );
    if (!domain) {
      throw new Error('upsertPost requires a target domain.');
    }
    const resolvedTitle = payload.title || payload.post_title || payload.postTitle || '';
    const resolvedSlug =
      payload.slug || payload.post_name || payload.postName || slugifySdkTitle(resolvedTitle);
    const post = payload.post
      ? { ...payload.post }
      : {
          post_name: resolvedSlug,
          post_title: resolvedTitle,
          post_content: payload.content ?? payload.post_content ?? payload.postContent ?? '',
          post_status: payload.post_status || 'publish',
          ...(payload.post_modified || payload.postModified
            ? { post_modified: payload.post_modified || payload.postModified }
            : {}),
          ...(payload.meta_title ? { meta_title: payload.meta_title } : {}),
          ...(payload.meta_description ? { meta_description: payload.meta_description } : {})
        };

    const syncAttachment = this._resolveSyncProofAttachment({
      ...payload,
      domain,
      post
    });

    const extraHeaders = {};
    const bodyObj = {
      domain,
      post
    };
    if (payload.conversationId || this.conversationId) {
      bodyObj.conversationId = payload.conversationId || this.conversationId;
    }
    if (syncAttachment) {
      extraHeaders['X-GitHub-Sync-Proof'] = syncAttachment.headerValue;
      bodyObj.githubSyncProof = syncAttachment.proof;
    }

    const res = await this.fetchImpl(`${this.baseUrl}/api/cms/posts/upsert`, {
      method: 'POST',
      headers: this._headers(extraHeaders),
      body: JSON.stringify(bodyObj)
    });
    if (!res.ok) {
      throw new Error(`CMS upsertPost returned HTTP ${res.status}`);
    }
    return res.json();
  }

  /**
   * Publishes an article via /api/cms/posts/upsert or /api/a2a/x402/publish with optional GitHubSyncProof.
   */
  async publishArticle(payload = {}) {
    if (!payload.x402Payment && !payload.useX402) {
      return this.upsertPost(payload);
    }
    const domain = cleanSdkDomain(payload.targetDomain || payload.domain || '');
    const syncAttachment = this._resolveSyncProofAttachment({
      ...payload,
      domain
    });
    const extraHeaders = {};
    if (payload.x402Payment) {
      extraHeaders['X-PAYMENT'] =
        typeof payload.x402Payment === 'string'
          ? payload.x402Payment
          : Buffer.from(JSON.stringify(payload.x402Payment), 'utf8').toString('base64');
    }
    const bodyObj = { ...payload };
    delete bodyObj.syncProofOptions;
    delete bodyObj.x402Payment;
    delete bodyObj.useX402;
    if (syncAttachment) {
      extraHeaders['X-GitHub-Sync-Proof'] = syncAttachment.headerValue;
      bodyObj.githubSyncProof = syncAttachment.proof;
    }

    const res = await this.fetchImpl(`${this.baseUrl}/api/a2a/x402/publish`, {
      method: 'POST',
      headers: this._headers(extraHeaders),
      body: JSON.stringify(bodyObj)
    });
    if (!res.ok) {
      throw new Error(`publishArticle returned HTTP ${res.status}`);
    }
    return res.json();
  }

  /**
   * Calls an MCP tool via JSON-RPC (`tools/call`). Automatically computes and attaches
   * `X-GitHub-Sync-Proof` and `githubSyncProof` when calling `cms_upsert_post` with syncProofOptions.
   */
  async callTool(toolName, toolArgs = {}, options = {}) {
    if (!toolName) {
      throw new Error('callTool requires a toolName.');
    }
    const argsCopy = { ...toolArgs };
    const syncAttachment = this._resolveSyncProofAttachment({
      ...argsCopy,
      githubSyncProof: options.githubSyncProof ?? argsCopy.githubSyncProof,
      syncProofOptions: options.syncProofOptions ?? argsCopy.syncProofOptions
    });
    delete argsCopy.syncProofOptions;

    const extraHeaders = {};
    if (syncAttachment) {
      extraHeaders['X-GitHub-Sync-Proof'] = syncAttachment.headerValue;
      argsCopy.githubSyncProof = syncAttachment.proof;
    }

    const rpcBody = {
      jsonrpc: '2.0',
      id: options.id || `mcp_${Date.now()}`,
      method: 'tools/call',
      params: {
        name: toolName,
        arguments: argsCopy
      }
    };

    const res = await this.fetchImpl(`${this.baseUrl}/api/mcp/rpc`, {
      method: 'POST',
      headers: this._headers(extraHeaders),
      body: JSON.stringify(rpcBody)
    });
    if (!res.ok) {
      throw new Error(`MCP callTool(${toolName}) returned HTTP ${res.status}`);
    }
    return res.json();
  }

  async createFreeInvoice(payload) {
    if (!payload || !payload.clientName || !Array.isArray(payload.items) || payload.items.length === 0) {
      throw new Error('createFreeInvoice requires clientName and a non-empty items[] array.');
    }
    const res = await this.fetchImpl('https://freeinvoicer.com/api/a2a/invoices/create-and-send', {
      method: 'POST',
      headers: this._headers(),
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      throw new Error(`FreeInvoicer API returned HTTP ${res.status}`);
    }
    return res.json();
  }

  async submitBinaryForensicsTriage(payload) {
    if (!payload || !payload.artifactName || !payload.targetArchitecture) {
      throw new Error('submitBinaryForensicsTriage requires artifactName and targetArchitecture.');
    }
    const res = await this.fetchImpl('https://digitalspying.com/api/a2a/reverse-engineering/triage', {
      method: 'POST',
      headers: this._headers(),
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      throw new Error(`DigitalSpying Triage API returned HTTP ${res.status}`);
    }
    return res.json();
  }
}

module.exports = {
  WinWinHostMcpClient,
  DOCUMENTATION_HUB_URLS,
  BENCHMARK_SAMPLE_DOMAINS,
  DEFAULT_SYNC_PROOF_SECRET,
  PROOF_TIMESTAMP_TOLERANCE_MS,
  computeContentSha256,
  deriveAgentSyncProofSecret,
  createGitHubSyncProof,
  encodeGitHubSyncProofHeader,
  parseGitHubSyncProof,
  verifyGitHubSyncProof
};
