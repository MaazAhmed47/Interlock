import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(
  path.join(process.env.SDK_NODE_ROOT, "package.json"),
);
const { McpServer, createMcpHandler } = require("@modelcontextprotocol/server");
const { z } = require("zod");

const handler = createMcpHandler(
  () => {
    const server = new McpServer({
      name: "interlock-strict-sdk-fixture",
      version: "2.0.0",
    });
    server.registerTool(
      "read_document",
      {
        description: "Read one internal document.",
        inputSchema: z.object({ document_id: z.string() }),
      },
      async ({ document_id }) => ({
        content: [{ type: "text", text: `safe:${document_id}` }],
        isError: false,
      }),
    );
    return server;
  },
  { legacy: "reject", responseMode: "json" },
);

const server = http.createServer(async (incoming, outgoing) => {
  const chunks = [];
  for await (const chunk of incoming) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  const url = new URL(
    incoming.url,
    `http://127.0.0.1:${server.address().port}`,
  );
  const request = new Request(url, {
    method: incoming.method,
    headers: incoming.headers,
    body: body.length ? body : undefined,
  });
  const parsed = body.length ? JSON.parse(body.toString("utf8")) : null;
  if (parsed?.method) {
    const selectedHeaders = {};
    for (const name of [
      "accept",
      "content-type",
      "mcp-protocol-version",
      "mcp-method",
      "mcp-name",
    ]) {
      if (request.headers.has(name))
        selectedHeaders[name] = request.headers.get(name);
    }
    process.stderr.write(
      `${JSON.stringify({ headers: selectedHeaders, body: parsed })}\n`,
    );
  }
  const response = await handler.fetch(request);
  outgoing.statusCode = response.status;
  for (const [name, value] of response.headers) outgoing.setHeader(name, value);
  outgoing.end(Buffer.from(await response.arrayBuffer()));
});

server.listen(0, "127.0.0.1", () => {
  process.stdout.write(`${server.address().port}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await handler.close();
    server.close(() => process.exit(0));
  });
}
