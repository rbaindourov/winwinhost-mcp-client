#!/usr/bin/env node
'use strict';

const {
  WinWinHostMcpClient,
  DOCUMENTATION_HUB_URLS,
  NETWORK_SAMPLE_DOMAINS
} = require('../index');

async function main() {
  const args = process.argv.slice(2);
  const client = new WinWinHostMcpClient({
    apiKey: process.env.WINWINHOST_API_KEY || ''
  });

  if (args.includes('--discover')) {
    const manifest = await client.discoverMcpManifest();
    console.log(JSON.stringify(manifest, null, 2));
    return;
  }

  if (args.includes('--config')) {
    const targetIdx = args.indexOf('--config');
    const target = args[targetIdx + 1] || 'claude_desktop_config.json';
    const cfg = await client.getClientConfig(target);
    console.log(JSON.stringify(cfg, null, 2));
    return;
  }

  console.log('=== @winwinhost/mcp-agent-client — Documentation Directory ===');
  console.log(JSON.stringify({ documentationHubs: DOCUMENTATION_HUB_URLS, sampleDomains: NETWORK_SAMPLE_DOMAINS }, null, 2));
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[winwinhost-mcp] Error:', err.message);
    process.exit(1);
  });
}
