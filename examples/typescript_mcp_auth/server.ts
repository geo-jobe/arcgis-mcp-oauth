import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";
import express, { type NextFunction, type Request, type Response } from "express";

export interface Settings {
  authServiceUrl: string;
  internalApiKey: string;
  publicBaseUrl: string;
}

interface ArcGISSession {
  accessToken: string;
  portalUrl: string;
  apiRoot: string;
  username?: string;
}

interface McpConnection {
  session: ArcGISSession;
  server: McpServer;
  transport: StreamableHTTPServerTransport;
}

interface SessionResponse {
  active?: boolean;
  resource?: unknown;
  arcgis_token?: { access_token?: unknown; username?: unknown };
  portal?: { portal_url?: unknown; api_root?: unknown };
}

export function settingsFromEnvironment(environment = process.env): Settings {
  const internalApiKey = environment.INTERNAL_API_KEY;
  if (!internalApiKey) {
    throw new Error("INTERNAL_API_KEY must be set");
  }

  return {
    authServiceUrl: (environment.AUTH_SERVICE_URL ?? "http://localhost:3324").replace(/\/+$/, ""),
    internalApiKey,
    publicBaseUrl: (environment.MCP_PUBLIC_BASE_URL ?? "http://localhost:3325").replace(/\/+$/, ""),
  };
}

export function extractBearer(authorization: string | undefined): string | undefined {
  const [scheme, token] = authorization?.split(/\s+/, 2) ?? [];
  return scheme?.toLowerCase() === "bearer" && token ? token : undefined;
}

export function resourceUri(settings: Settings): string {
  return `${settings.publicBaseUrl}/mcp`;
}

export async function resolveSession(
  settings: Settings,
  mcpAccessToken: string,
): Promise<ArcGISSession | undefined> {
  const resource = resourceUri(settings);
  let response: globalThis.Response;
  try {
    response = await fetch(`${settings.authServiceUrl}/internal/session`, {
      headers: {
        // This is the resource server's credential, not the user's MCP token.
        Authorization: `Bearer ${settings.internalApiKey}`,
        "X-MCP-Access-Token": mcpAccessToken,
        "X-MCP-Resource": resource,
      },
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    return undefined;
  }

  if (!response.ok) {
    return undefined;
  }

  let payload: SessionResponse;
  try {
    payload = (await response.json()) as SessionResponse;
  } catch {
    return undefined;
  }

  const accessToken = payload.arcgis_token?.access_token;
  const portalUrl = payload.portal?.portal_url;
  const apiRoot = payload.portal?.api_root;
  if (
    !payload.active ||
    payload.resource !== resource ||
    typeof accessToken !== "string" ||
    typeof portalUrl !== "string" ||
    typeof apiRoot !== "string"
  ) {
    return undefined;
  }

  return {
    accessToken,
    portalUrl,
    apiRoot,
    username: typeof payload.arcgis_token?.username === "string" ? payload.arcgis_token.username : undefined,
  };
}

function unauthorized(response: Response, metadataUrl: string, error?: string): void {
  const challenge = error
    ? `Bearer error="${error}", resource_metadata="${metadataUrl}"`
    : `Bearer resource_metadata="${metadataUrl}"`;
  response.status(401).set("WWW-Authenticate", challenge).json({
    detail: "A valid MCP bearer token is required.",
  });
}

function createMcpServer(getSession: () => ArcGISSession): McpServer {
  const server = new McpServer({ name: "ArcGIS-protected TypeScript example", version: "1.0.0" });

  server.registerTool(
    "current_arcgis_user",
    {
      description: "Return the authenticated ArcGIS user's public profile information.",
      inputSchema: {},
    },
    async () => {
      try {
        const session = getSession();
        // The ArcGIS token is sent only to the selected portal and never returned.
        const response = await fetch(`${session.apiRoot}/community/self?f=json&token=${encodeURIComponent(session.accessToken)}`, {
          signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) {
          throw new Error(`ArcGIS returned HTTP ${response.status}`);
        }
        const profile = (await response.json()) as { username?: unknown; fullName?: unknown };
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                username: typeof profile.username === "string" ? profile.username : session.username ?? null,
                full_name: typeof profile.fullName === "string" ? profile.fullName : null,
                portal_url: session.portalUrl,
              }),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: "text" as const, text: `Unable to retrieve the ArcGIS profile: ${String(error)}` }],
        };
      }
    },
  );

  return server;
}

function mcpError(response: Response, status: number, message: string): void {
  response.status(status).json({
    jsonrpc: "2.0",
    error: { code: -32000, message },
    id: null,
  });
}

export function buildApp(settings: Settings) {
  const app = express();
  const resource = resourceUri(settings);
  const metadataUrl = `${settings.publicBaseUrl}/.well-known/oauth-protected-resource/mcp`;
  const connections = new Map<string, McpConnection>();

  const protectedResourceMetadata = (_request: Request, response: Response) => {
    response.json({
      resource,
      authorization_servers: [settings.authServiceUrl],
      bearer_methods_supported: ["header"],
      scopes_supported: ["profile", "email"],
    });
  };
  app.get("/.well-known/oauth-protected-resource", protectedResourceMetadata);
  app.get("/.well-known/oauth-protected-resource/mcp", protectedResourceMetadata);

  async function authenticate(request: Request, response: Response): Promise<ArcGISSession | undefined> {
    const mcpAccessToken = extractBearer(request.header("authorization"));
    if (!mcpAccessToken) {
      unauthorized(response, metadataUrl);
      return undefined;
    }

    const session = await resolveSession(settings, mcpAccessToken);
    if (!session) {
      unauthorized(response, metadataUrl, "invalid_token");
      return undefined;
    }

    return session;
  }

  async function handleMcpPost(request: Request, response: Response, next: NextFunction): Promise<void> {
    const session = await authenticate(request, response);
    if (!session) {
      return;
    }

    const sessionId = request.header("mcp-session-id");
    let connection = sessionId ? connections.get(sessionId) : undefined;

    try {
      if (connection) {
        // Resolve on each request so an expired ArcGIS session is never retained.
        connection.session = session;
        await connection.transport.handleRequest(request, response, request.body);
        return;
      }

      if (sessionId || !isInitializeRequest(request.body)) {
        mcpError(response, sessionId ? 404 : 400, sessionId ? "Session not found" : "Initialize the MCP session first");
        return;
      }

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        onsessioninitialized: (initializedSessionId) => {
          connections.set(initializedSessionId, connection!);
        },
      });
      const server = createMcpServer(() => connection!.session);
      connection = { session, server, transport };
      transport.onclose = () => {
        if (transport.sessionId) {
          connections.delete(transport.sessionId);
        }
        void server.close();
      };
      await server.connect(transport);
      await transport.handleRequest(request, response, request.body);
    } catch (error) {
      next(error);
    }
  }

  async function handleMcpSessionRequest(request: Request, response: Response, next: NextFunction): Promise<void> {
    const session = await authenticate(request, response);
    if (!session) {
      return;
    }

    const sessionId = request.header("mcp-session-id");
    const connection = sessionId ? connections.get(sessionId) : undefined;
    if (!connection) {
      mcpError(response, sessionId ? 404 : 400, sessionId ? "Session not found" : "Mcp-Session-Id header is required");
      return;
    }

    try {
      connection.session = session;
      await connection.transport.handleRequest(request, response);
    } catch (error) {
      next(error);
    }
  }

  app.post("/mcp", express.json(), handleMcpPost);
  app.get("/mcp", handleMcpSessionRequest);
  app.delete("/mcp", handleMcpSessionRequest);

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const app = buildApp(settingsFromEnvironment());
  app.listen(3325, "127.0.0.1", () => {
    console.log("TypeScript MCP example listening at http://localhost:3325/mcp");
  });
}
