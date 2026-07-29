import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(
  path.join(process.env.SDK_NODE_ROOT, "package.json"),
);
const {
  Client,
  StreamableHTTPClientTransport,
} = require("@modelcontextprotocol/client");

const url = new URL(process.env.SDK_PROBE_URL);
const transport = new StreamableHTTPClientTransport(url, {
  requestInit: { headers: { "X-API-Key": process.env.SDK_PROBE_KEY } },
});
const client = new Client(
  { name: "interlock-typescript-sdk-probe", version: "2.0.0" },
  {
    capabilities: {},
    versionNegotiation: { mode: { pin: "2026-07-28" } },
  },
);

let outcome;
try {
  await client.connect(transport);
  const listed = await client.listTools();
  const called = await client.callTool({
    name: "read_document",
    arguments: { document_id: "safe" },
  });
  outcome = {
    connected: true,
    server_name: client.getServerVersion()?.name ?? null,
    tool_names: listed.tools.map((tool) => tool.name),
    call_is_error: called.isError ?? false,
  };
} catch (error) {
  outcome = {
    connected: false,
    error_type: error?.constructor?.name ?? typeof error,
  };
} finally {
  await client.close().catch(() => {});
}

process.stdout.write(`${JSON.stringify(outcome)}\n`);
