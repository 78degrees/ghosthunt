/**
 * index.ts — Entry point for GhostHunt MCP server.
 *
 * Starts a stdio transport so Claude Desktop (or any MCP client)
 * can communicate with the scanner.
 *
 * Usage:
 *   npx ghosthunt          # run directly
 *   node dist/index.js     # after build
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

async function main() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("GhostHunt failed to start:", error);
  process.exit(1);
});
