# cf-domain-mcp

MCP server (FastMCP) packaged for MCP Bundles (`.mcpb`) that batch-checks domain availability using GoDaddy's API.

## Tool

- `check_domain_availability_batch`
  - Input:
    - `labels: string[]` (required, base labels only like `"acme"`, not FQDNs)
    - `tlds?: string[]` (optional, defaults to `com` and `ai`)
  - Output:
    - Batch status (`ok | partial | failed`)
    - Summary counters
    - Per-label checks and errors
    - Per-domain check keys are GoDaddy-native: `domain`, `available`, `definitive`, `price`, `currency`, `period`
    - `price` is converted from GoDaddy micro-units to decimal

## GoDaddy config

Configured through MCPB `user_config` in [manifest.json](manifest.json):

- `gd_api_key`
- `gd_api_secret`
- `gd_environment` (`ote` or `production`)
- optional batch limit values

## Local development

1. Install dependencies with uv:
  - `uv sync`
2. Set env vars for local run:
  - `GD_API_KEY`
  - `GD_API_SECRET`
  - `GD_ENVIRONMENT`
3. Start server:
  - `uv run server/main.py`

## MCPB packaging

1. Install CLI: `npm install -g @anthropic-ai/mcpb`
2. Validate: `mcpb validate`
3. Pack: `mcpb pack`

## Notes

- Uses GoDaddy Domains API endpoint:
  - `POST /v1/domains/available`
- Uses GoDaddy bulk availability checks (up to 500 domains per upstream request).
- Includes retry/backoff for transient errors and `429` responses.
