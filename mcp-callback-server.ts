/**
 * MCP OAuth Callback Server
 * 
 * HTTP server that handles OAuth callbacks from the authorization server.
 * Uses Node.js http module for compatibility.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from "http"
import { getAppName } from "./agent-dir.ts"
import {
  DEFAULT_OAUTH_CALLBACK_HOST,
  DEFAULT_OAUTH_CALLBACK_PATH,
  getConfiguredOAuthCallbackPort,
  getOAuthCallbackHost,
  getOAuthCallbackPath,
  getOAuthCallbackPort,
  setOAuthCallbackHost,
  setOAuthCallbackPath,
  setOAuthCallbackPort,
} from "./mcp-oauth-provider.ts"

// HTML templates for callback responses.
//
// These pages are served from localhost during OAuth and are the last thing a
// user sees before returning to their terminal, so they are self-contained: no
// webfonts, no external assets, nothing that needs the network. They also name
// the host rather than hardcoding "Pi", so a distribution that rebrands pi
// (arc, tau, …) does not send its users back to an app they are not running.

/** Shared chrome: system fonts, a centred card, and light/dark support. */
const PAGE_STYLE = `
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      background: #0f1117;
      color: #e6e8ee;
    }
    .card {
      width: 100%;
      max-width: 26rem;
      padding: 2.5rem 2rem;
      text-align: center;
      background: #161922;
      border: 1px solid #242938;
      border-radius: 14px;
      box-shadow: 0 1px 2px rgba(0,0,0,.3), 0 12px 32px rgba(0,0,0,.25);
    }
    .badge {
      width: 3rem; height: 3rem;
      margin: 0 auto 1.25rem;
      display: grid; place-items: center;
      border-radius: 50%;
    }
    .badge svg { width: 1.5rem; height: 1.5rem; display: block; }
    .ok   { background: rgba(74,222,128,.12); color: #4ade80; }
    .bad  { background: rgba(248,113,113,.12); color: #f87171; }
    h1 { margin: 0 0 .5rem; font-size: 1.15rem; font-weight: 600; letter-spacing: -0.01em; }
    p  { margin: 0; color: #9aa1b1; }
    .app { color: #e6e8ee; font-weight: 500; }
    .hint { margin-top: 1.25rem; font-size: .8125rem; color: #6b7280; }
    code {
      display: block;
      margin-top: 1.25rem;
      padding: .75rem .875rem;
      text-align: left;
      font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
      color: #fca5a5;
      background: rgba(248,113,113,.08);
      border: 1px solid rgba(248,113,113,.2);
      border-radius: 8px;
      overflow-wrap: anywhere;
    }
    @media (prefers-color-scheme: light) {
      body { background: #f6f7f9; color: #121620; }
      .card { background: #fff; border-color: #e4e7ee; }
      p { color: #5b6474; }
      .app { color: #121620; }
      .hint { color: #8b93a3; }
    }`

const CHECK_ICON =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>'

const CROSS_ICON =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>'

function page(options: {
  title: string
  heading: string
  body: string
  icon: string
  tone: "ok" | "bad"
  extra?: string
  autoClose?: boolean
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${options.title}</title>
  <style>${PAGE_STYLE}
  </style>
</head>
<body>
  <main class="card">
    <div class="badge ${options.tone}">${options.icon}</div>
    <h1>${options.heading}</h1>
    <p>${options.body}</p>
    ${options.extra ?? ""}
  </main>
${options.autoClose ? "  <script>setTimeout(() => window.close(), 2000);</script>\n" : ""}</body>
</html>`
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

/** Built per request so a host that sets PI_PACKAGE_DIR late is still named right. */
function htmlSuccess(): string {
  const app = escapeHtml(getAppName())
  return page({
    title: `${app} — Authorization Successful`,
    heading: "Authorization Successful",
    body: `You can close this window and return to <span class="app">${app}</span>.`,
    icon: CHECK_ICON,
    tone: "ok",
    autoClose: true,
  })
}

function htmlManualSuccess(): string {
  const app = escapeHtml(getAppName())
  return page({
    title: `${app} — Authorization Received`,
    heading: "Authorization Received",
    body: `Copy the full callback URL from your browser address bar and paste it back into <span class="app">${app}</span> with auth-complete.`,
    icon: CHECK_ICON,
    tone: "ok",
  })
}

function htmlError(error: string): string {
  const app = escapeHtml(getAppName())
  return page({
    title: `${app} — Authorization Failed`,
    heading: "Authorization Failed",
    body: `Something went wrong during authorization. You can close this window and try again from <span class="app">${app}</span>.`,
    icon: CROSS_ICON,
    tone: "bad",
    extra: `<code>${escapeHtml(error)}</code>`,
  })
}

/** Result of a successful OAuth callback */
export interface OAuthCallbackResult {
  code: string
  /** RFC 9207 `iss` authorization response parameter, when provided */
  iss?: string
}

/** Pending authorization request */
interface PendingAuth {
  resolve: (result: OAuthCallbackResult) => void
  reject: (error: Error) => void
  timeout: ReturnType<typeof setTimeout>
}

/** Server singleton state */
let servers = new Map<string, Server>()
let bindingPromise: Promise<void> | undefined
let stoppingPromise: Promise<void> | undefined
let restartableStoppingPromise: Promise<void> | undefined
let callbackGeneration = 0
const pendingAuths = new Map<string, PendingAuth>()
const reservedAuthStates = new Set<string>()

/**
 * Loopback addresses the callback listener binds.
 *
 * RFC 8252 section 7.3 recommends that clients bind both IPv4 and IPv6
 * loopback and use whichever is available, because a host is not guaranteed
 * to have both. Binding the whole set also means a redirect_uri naming any
 * loopback spelling (127.0.0.1, ::1, or localhost, which resolves to one of
 * them) reaches this listener. That is what lets a pending authorization on
 * the default host coexist with a separately configured loopback redirect
 * instead of forcing a host switch.
 */
const LOOPBACK_CALLBACK_HOSTS = ["127.0.0.1", "::1"] as const

/** Hostnames that name the loopback interface rather than an address to bind. */
const LOOPBACK_ALIASES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"])

function isLoopbackAlias(host: string): boolean {
  return LOOPBACK_ALIASES.has(host.toLowerCase())
}

/** Whether `host` is a loopback address literal rather than a name that resolves to one. */
function isLoopbackIpLiteral(host: string): boolean {
  return (LOOPBACK_CALLBACK_HOSTS as readonly string[]).includes(host)
}

/** Whether the already-bound listeners can serve a redirect for `requestedHost`. */
function boundHostsCoverRequest(bound: Map<string, Server>, requestedHost: string): boolean {
  if (bound.size === 0) return true
  if (bound.has(requestedHost)) return true
  if (!isLoopbackAlias(requestedHost)) return false
  return LOOPBACK_CALLBACK_HOSTS.every((host) => bound.has(host))
}

/** Timeout for callback completion (5 minutes) */
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000

interface EnsureCallbackServerOptions {
  strictPort?: boolean
  port?: number
  callbackHost?: string
  callbackPath?: string
  oauthState?: string
  reserveState?: boolean
}

/**
 * The loopback host is owned by `mcp-oauth-provider.ts` so the bind address
 * and the redirect URI advertised to the authorization server can never
 * drift apart. See DEFAULT_OAUTH_CALLBACK_HOST there.
 */

/**
 * Handle incoming HTTP requests to the callback server.
 */
function handleRequest(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url || "/", `http://${req.headers.host}`)

  // Only handle the callback path
  if (url.pathname !== getOAuthCallbackPath()) {
    res.writeHead(404, { "Content-Type": "text/plain" })
    res.end("Not found")
    return
  }

  const code = url.searchParams.get("code")
  const iss = url.searchParams.get("iss")
  const state = url.searchParams.get("state")
  const error = url.searchParams.get("error")
  const errorDescription = url.searchParams.get("error_description")

  // Enforce state parameter presence for CSRF protection
  if (!state) {
    const errorMsg = "Missing required state parameter - potential CSRF attack"
    res.writeHead(400, { "Content-Type": "text/html" })
    res.end(htmlError(errorMsg))
    return
  }

  const pending = pendingAuths.get(state)
  const isReserved = reservedAuthStates.has(state)

  // Handle OAuth errors only for a state that belongs to an active flow.
  if (error) {
    if (!pending && !isReserved) {
      const errorMsg = "Invalid or expired state parameter - potential CSRF attack"
      res.writeHead(400, { "Content-Type": "text/html" })
      res.end(htmlError(errorMsg))
      return
    }

    const errorMsg = errorDescription || error
    // Send HTTP response first before rejecting promise
    res.writeHead(200, { "Content-Type": "text/html" })
    res.end(htmlError(errorMsg))
    // Reject promise after response is sent (defer to allow test to attach handler)
    if (pending) {
      reservedAuthStates.delete(state)
      clearTimeout(pending.timeout)
      pendingAuths.delete(state)
      setTimeout(() => pending.reject(new Error(errorMsg)), 0)
    }
    return
  }

  // Validate state parameter
  if (!pending && !isReserved) {
    const errorMsg = "Invalid or expired state parameter - potential CSRF attack"
    res.writeHead(400, { "Content-Type": "text/html" })
    res.end(htmlError(errorMsg))
    return
  }

  // Require authorization code
  if (!code) {
    res.writeHead(400, { "Content-Type": "text/html" })
    res.end(htmlError("No authorization code provided"))
    return
  }

  if (!pending) {
    res.writeHead(200, { "Content-Type": "text/html" })
    res.end(htmlManualSuccess())
    return
  }

  // Clear timeout and resolve the pending promise
  clearTimeout(pending.timeout)
  pendingAuths.delete(state)
  pending.resolve({ code, ...(iss !== null ? { iss } : {}) })

  res.writeHead(200, { "Content-Type": "text/html" })
  res.end(htmlSuccess())
}

/**
 * Ensure the callback server is running.
 * If strictPort is true, requires binding on the configured callback port.
 * If strictPort is false, asks the OS for an available local port.
 */
export async function ensureCallbackServer(options: EnsureCallbackServerOptions = {}): Promise<void> {
  const generation = callbackGeneration
  if (stoppingPromise) {
    if (!restartableStoppingPromise) {
      throw new Error("OAuth callback server stopped")
    }
    await restartableStoppingPromise
    if (generation !== callbackGeneration) {
      throw new Error("OAuth callback server stopped")
    }
  }
  while (bindingPromise) {
    await bindingPromise
    if (generation !== callbackGeneration) {
      throw new Error("OAuth callback server stopped")
    }
  }
  if (generation !== callbackGeneration) {
    throw new Error("OAuth callback server stopped")
  }

  const operation = ensureCallbackServerLocked(options)
  bindingPromise = operation
  try {
    await operation
  } finally {
    if (bindingPromise === operation) {
      bindingPromise = undefined
    }
  }
}

async function ensureCallbackServerLocked(options: EnsureCallbackServerOptions = {}): Promise<void> {
  const requiredPort = options.port ?? getConfiguredOAuthCallbackPort()
  const strictPort = options.strictPort === true
  const requestedHost = options.callbackHost ?? DEFAULT_OAUTH_CALLBACK_HOST
  const rawRequestedPath = options.callbackPath ?? DEFAULT_OAUTH_CALLBACK_PATH
  const requestedPath = rawRequestedPath.startsWith("/") ? rawRequestedPath : `/${rawRequestedPath}`
  if (options.reserveState && !options.oauthState) {
    throw new Error("OAuth callback reservation requires an oauthState")
  }
  let reservedState: string | undefined

  const previousServers = servers
  const needsStrictRebind = Boolean(previousServers.size > 0 && strictPort && getOAuthCallbackPort() !== requiredPort)
  const needsHostSwitch = !boundHostsCoverRequest(previousServers, requestedHost)
  const needsPathSwitch = Boolean(previousServers.size > 0 && getOAuthCallbackPath() !== requestedPath)

  if (previousServers.size > 0) {
    if (!needsStrictRebind && !needsHostSwitch) {
      if (needsPathSwitch) {
        if (pendingAuths.size > 0 || reservedAuthStates.size > 0) {
          throw new Error(
            `OAuth callback server is using path ${getOAuthCallbackPath()}, but callback path ${requestedPath} is required and cannot be switched while authorizations are pending`
          )
        }
        setOAuthCallbackPath(requestedPath)
      }
      if (options.reserveState && options.oauthState) {
        reservedAuthStates.add(options.oauthState)
        reservedState = options.oauthState
      }
      return
    }

    if (pendingAuths.size > 0 || reservedAuthStates.size > 0) {
      throw new Error(
        `OAuth callback server is running on ${getOAuthCallbackHost()}:${getOAuthCallbackPort()}, but strict callback endpoint ${requestedHost}:${requiredPort} is required and cannot be switched while authorizations are pending`
      )
    }
  }

  // Every loopback alias resolves to one of these, so binding the set keeps a
  // pending authorization from blocking a differently spelled loopback redirect.
  const targetHosts = isLoopbackAlias(requestedHost) ? [...LOOPBACK_CALLBACK_HOSTS] : [requestedHost]
  // What the advertised redirect actually depends on:
  //
  // - A configured address literal appears verbatim in the redirect_uri, so
  //   that exact address must bind. Failing it would hand the authorization
  //   code to whoever holds it.
  // - A configured `localhost` is a name that may resolve to either family, so
  //   every loopback address must bind. Binding one and still advertising
  //   `localhost` leaves the browser free to pick the address we did not hold.
  // - The default is not load-bearing: the advertised redirect is composed from
  //   whichever address ends up bound, so an absent family cannot strand it and
  //   one bound address suffices.
  const configuredHost = options.callbackHost
  const requiredHost = configuredHost !== undefined && isLoopbackIpLiteral(requestedHost)
    ? requestedHost
    : undefined
  const requireAllLoopback = configuredHost !== undefined
    && isLoopbackAlias(requestedHost)
    && !isLoopbackIpLiteral(requestedHost)
  const opened = new Map<string, Server>()
  let lastError: unknown

  try {
    for (const host of targetHosts) {
      const candidateServer = createServer(handleRequest)
      // The first bind decides the port so every listener shares one.
      const listenPort = opened.size === 0 ? (strictPort ? requiredPort : 0) : getOAuthCallbackPort()
      try {
        await new Promise<void>((resolve, reject) => {
          candidateServer.once("error", reject)
          candidateServer.listen(listenPort, host, resolve)
        })
        const address = candidateServer.address()
        if (!address || typeof address === "string" || typeof address.port !== "number") {
          throw new Error("OAuth callback server did not report an assigned port")
        }
        // In strict mode the port was requested explicitly, so keep it verbatim
        // rather than re-reading it; otherwise adopt the assigned port.
        setOAuthCallbackPort(strictPort ? requiredPort : address.port)
        opened.set(host, candidateServer)
      } catch (error) {
        await new Promise<void>((resolve) => candidateServer.close(() => resolve()))
        // A redirect_uri naming this exact address depends on it. If it cannot
        // bind, whoever holds it would receive the authorization code, so fail
        // startup rather than advertise a callback this process never serves.
        if (host === requiredHost) throw error
        // An explicit `localhost` redirect can resolve to this address, so it
        // is required too: advertising a name the browser may resolve to an
        // address we failed to hold would deliver the code elsewhere.
        if (requireAllLoopback) throw error
        // Otherwise this is an optional loopback family: an absent one must not
        // block a host that is only IPv4 or only IPv6.
        lastError = error
        continue
      }
    }

    // Re-throw the underlying failure (not a synthesized one) so the
    // EADDRINUSE guidance below still reaches the caller.
    if (opened.size === 0) throw lastError

    if (previousServers.size > 0 && (needsStrictRebind || needsHostSwitch)) {
      await Promise.all([...previousServers.values()].map(
        (previous) => new Promise<void>((resolve) => previous.close(() => resolve())),
      ))
    }

    const activeHost = opened.has(DEFAULT_OAUTH_CALLBACK_HOST)
      ? DEFAULT_OAUTH_CALLBACK_HOST
      : opened.keys().next().value ?? DEFAULT_OAUTH_CALLBACK_HOST
    setOAuthCallbackHost(activeHost)
    setOAuthCallbackPath(requestedPath)
    servers = opened
    if (options.reserveState && options.oauthState) {
      reservedAuthStates.add(options.oauthState)
      reservedState = options.oauthState
    }
    for (const listener of opened.values()) listener.unref()
  } catch (error) {
    if (reservedState) {
      reservedAuthStates.delete(reservedState)
    }
    await Promise.all([...opened.values()].map(
      (listener) => new Promise<void>((resolve) => listener.close(() => resolve())),
    ))

    const nodeError = error as NodeJS.ErrnoException
    if (strictPort && nodeError.code === "EADDRINUSE") {
      throw new Error(
        `OAuth callback port ${requiredPort} is already in use. Pre-registered OAuth clients require an exact redirect URI; set MCP_OAUTH_CALLBACK_PORT to your registered port or free port ${requiredPort}`,
        { cause: error }
      )
    }

    throw error
  }
}

export function reserveCallbackServer(oauthState: string): void {
  reservedAuthStates.add(oauthState)
}

export function releaseCallbackServer(oauthState: string): void {
  reservedAuthStates.delete(oauthState)
}

/**
 * Wait for a callback with the given OAuth state.
 * Returns a promise that resolves with the authorization code and, when the
 * authorization server sends one, the RFC 9207 `iss` parameter.
 */
export function waitForCallback(oauthState: string): Promise<OAuthCallbackResult> {
  reservedAuthStates.delete(oauthState)
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      if (pendingAuths.has(oauthState)) {
        pendingAuths.delete(oauthState)
        reject(new Error("OAuth callback timeout - authorization took too long"))
      }
    }, CALLBACK_TIMEOUT_MS)

    pendingAuths.set(oauthState, { resolve, reject, timeout })
  })
}

/**
 * Cancel a pending authorization by state.
 */
export function cancelPendingCallback(oauthState: string): void {
  reservedAuthStates.delete(oauthState)
  const pending = pendingAuths.get(oauthState)
  if (pending) {
    clearTimeout(pending.timeout)
    pendingAuths.delete(oauthState)
    pending.reject(new Error("Authorization cancelled"))
  }
}

/**
 * Stop the callback server and reject all pending authorizations.
 */
export function stopCallbackServer(): Promise<void> {
  if (stoppingPromise) {
    restartableStoppingPromise = undefined
    callbackGeneration += 1
    return stoppingPromise
  }

  callbackGeneration += 1
  const cleanup = (async () => {
    while (bindingPromise) {
      await bindingPromise.catch(() => {})
    }

    if (servers.size > 0) {
      await Promise.all([...servers.values()].map(
        (listener) => new Promise<void>((resolve) => listener.close(() => resolve())),
      ))
      servers = new Map()
    }

    setOAuthCallbackPort(getConfiguredOAuthCallbackPort())
    setOAuthCallbackHost(DEFAULT_OAUTH_CALLBACK_HOST)
    setOAuthCallbackPath(DEFAULT_OAUTH_CALLBACK_PATH)

    // Reject all pending auths (defer to allow any pending operations to complete)
    const pendingList = Array.from(pendingAuths.entries())
    pendingAuths.clear()
    reservedAuthStates.clear()
    setTimeout(() => {
      for (const [, pending] of pendingList) {
        clearTimeout(pending.timeout)
        pending.reject(new Error("OAuth callback server stopped"))
      }
    }, 0)
  })()

  const operation = cleanup.finally(() => {
    if (stoppingPromise === operation) stoppingPromise = undefined
  })
  stoppingPromise = operation
  return operation
}

/** Stop the callback server only when no bind or authorization owns it. */
export function stopCallbackServerIfIdle(): Promise<void> {
  if (stoppingPromise) return stoppingPromise
  if (bindingPromise || servers.size === 0 || pendingAuths.size > 0 || reservedAuthStates.size > 0) {
    return Promise.resolve()
  }
  const operation = stopCallbackServer().finally(() => {
    if (restartableStoppingPromise === operation) restartableStoppingPromise = undefined
  })
  restartableStoppingPromise = operation
  return operation
}

/**
 * Check if the callback server is running.
 */
export function isCallbackServerRunning(): boolean {
  return servers.size > 0
}

/**
 * Get the number of pending authorizations.
 */
export function getPendingAuthCount(): number {
  return pendingAuths.size
}
