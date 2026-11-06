export interface WinWinHostMcpClientOptions {
  baseUrl?: string;
  apiKey?: string;
  syncProofSecret?: string;
  agentId?: string;
  conversationId?: string;
  affiliateRef?: string;
  fetchImpl?: typeof fetch;
}

export interface GitHubSyncProof {
  commitSha: string;
  branch: string;
  domain: string;
  slug: string;
  contentSha256: string;
  agentId: string;
  conversationId: string;
  timestamp: number;
  signature: string;
}

export interface SyncProofOptions {
  commitSha?: string;
  branch?: string;
  agentId?: string;
  conversationId?: string;
  secret?: string;
  timestamp?: number | string;
  cwd?: string;
}

export interface CreateGitHubSyncProofParams extends SyncProofOptions {
  domain: string;
  slug?: string;
  postName?: string;
  post_name?: string;
  postTitle?: string;
  postContent?: string;
  post_content?: string;
  postModified?: string | Date;
  post_modified?: string | Date;
  contentSha256?: string;
}

export interface VerifyGitHubSyncProofExpected {
  domain?: string;
  slug?: string;
  postName?: string;
  post_name?: string;
  postTitle?: string;
  postContent?: string;
  rawPostContent?: string;
  postModified?: string | Date;
  existingPostModified?: string | Date;
  allowEmptyPostModifiedFallback?: boolean;
  branch?: string;
  now?: number;
  toleranceMs?: number;
  secret?: string;
  keyScope?: 'cluster_secret' | 'agent_scoped_secret';
  author?: string;
  attributedAuthor?: {
    username?: string;
    syncProofSecret?: string;
    apiKey?: string;
  } | null;
  agentSecrets?: string[] | string;
}

export interface VerifyGitHubSyncProofResult {
  valid: boolean;
  reason?: string;
  keyScope?: 'cluster_secret' | 'agent_scoped_secret';
  commitSha?: string;
  branch?: string;
  domain?: string;
  slug?: string;
  contentSha256?: string;
  agentId?: string;
  conversationId?: string;
  timestamp?: number;
}

export interface UpsertPostInput {
  domain?: string;
  targetDomain?: string;
  post?: Record<string, any>;
  slug?: string;
  post_name?: string;
  postName?: string;
  title?: string;
  post_title?: string;
  postTitle?: string;
  content?: string;
  post_content?: string;
  postContent?: string;
  post_status?: string;
  post_modified?: string;
  postModified?: string;
  meta_title?: string;
  meta_description?: string;
  conversationId?: string;
  githubSyncProof?: GitHubSyncProof | string;
  syncProofOptions?: SyncProofOptions;
}

export interface FreeInvoiceLineItem {
  description: string;
  quantity: number;
  unitPrice: number;
}

export interface CreateFreeInvoiceInput {
  businessName?: string;
  clientName: string;
  clientEmail?: string;
  currency?: string;
  items: FreeInvoiceLineItem[];
  sendEmail?: boolean;
}

export interface BinaryForensicsTriageInput {
  artifactName: string;
  targetArchitecture: string;
  artifactSha256?: string;
  contactEmail?: string;
}

export declare const DOCUMENTATION_HUB_URLS: Readonly<{
  masterGateway: string;
  articleSyndicatorPayPerPost: string;
  freeInvoicerZeroAuthMcp: string;
  webdesignerLaDesignAudit: string;
  digitalSpyingGhidraForensics: string;
  linkDepotDirectoryCitations: string;
  leadSuperstorePingTree: string;
  contactCampaignsOutreach: string;
  affiliatePartnersAttribution: string;
}>;

export declare const NETWORK_SAMPLE_DOMAINS: ReadonlyArray<string>;
export declare const DEFAULT_SYNC_PROOF_SECRET: string;
export declare const PROOF_TIMESTAMP_TOLERANCE_MS: number;

export declare function computeContentSha256(
  domainOrObj:
    | string
    | {
        domain: string;
        slug?: string;
        postName?: string;
        post_name?: string;
        postContent?: string;
        post_content?: string;
        postModified?: string | Date;
        post_modified?: string | Date;
      },
  slug?: string,
  postContent?: string,
  postModified?: string | Date
): string;

export declare function deriveAgentSyncProofSecret(
  authorRecordOrKey: any,
  optionalUsername?: string
): string;

export declare function createGitHubSyncProof(params: CreateGitHubSyncProofParams): GitHubSyncProof;
export declare function encodeGitHubSyncProofHeader(proof: GitHubSyncProof): string;
export declare function parseGitHubSyncProof(input: unknown): GitHubSyncProof | null;
export declare function verifyGitHubSyncProof(
  proof: unknown,
  expected?: VerifyGitHubSyncProofExpected
): VerifyGitHubSyncProofResult;

export declare class WinWinHostMcpClient {
  baseUrl: string;
  apiKey: string;
  syncProofSecret: string;
  agentId: string;
  conversationId: string;
  affiliateRef: string;
  constructor(options?: WinWinHostMcpClientOptions);
  discoverMcpManifest(domainOrBaseUrl?: string): Promise<Record<string, any>>;
  getClientConfig(target?: string): Promise<Record<string, any>>;
  upsertPost(payload: UpsertPostInput): Promise<Record<string, any>>;
  publishArticle(payload: Record<string, any>): Promise<Record<string, any>>;
  callTool(
    toolName: string,
    toolArgs?: Record<string, any>,
    options?: {
      id?: string;
      githubSyncProof?: GitHubSyncProof | string;
      syncProofOptions?: SyncProofOptions;
    }
  ): Promise<Record<string, any>>;
  createFreeInvoice(payload: CreateFreeInvoiceInput): Promise<Record<string, any>>;
  submitBinaryForensicsTriage(payload: BinaryForensicsTriageInput): Promise<Record<string, any>>;
}
