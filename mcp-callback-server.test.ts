/**
 * Tests for mcp-callback-server.ts - OAuth callback server
 */

import { describe, it, beforeEach, afterEach } from "node:test"
import assert from "node:assert"
import { createServer } from "node:http"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  ensureCallbackServer,
  waitForCallback,
  cancelPendingCallback,
  stopCallbackServer,
  isCallbackServerRunning,
  getPendingAuthCount,
  releaseCallbackServer,
} from "./mcp-callback-server.ts"
import { getConfiguredOAuthCallbackPort, getOAuthCallbackPath, getOAuthCallbackPort, McpOAuthProvider } from "./mcp-oauth-provider.ts"

/**
 * Occupy `port` on whichever loopback addresses this host actually has, so the
 * port is genuinely unavailable to the callback listener. A family that cannot
 * bind is skipped rather than failing the fixture, so these tests behave the
 * same on single-family and dual-stack hosts. The returned function always
 * closes every blocker that did open, including after a partial failure.
 */
async function squatPort(port: number): Promise<() => Promise<void>> {
  const opened: import("node:http").Server[] = []
  const release = async () => {
    for (const server of opened.splice(0)) {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  }
  try {
    for (const host of ["127.0.0.1", "::1"]) {
      const server = createServer((_req, res) => {
        res.writeHead(200)
        res.end("blocked")
      })
      try {
        await new Promise<void>((resolve, reject) => {
          server.once("error", reject)
          server.listen(port, host, () => resolve())
        })
        opened.push(server)
      } catch {
        // This family is unavailable here; the other one still blocks the port.
        await new Promise<void>((resolve) => server.close(() => resolve()))
      }
    }
  } catch (error) {
    await release()
    throw error
  }
  return release
}

async function getFreePort(): Promise<number> {
  const probe = createServer()
  await new Promise<void>((resolve, reject) => {
    probe.once("error", reject)
    probe.listen(0, "localhost", resolve)
  })
  const address = probe.address()
  await new Promise<void>((resolve) => probe.close(() => resolve()))
  if (!address || typeof address === "string") {
    throw new Error("Failed to reserve a free test port")
  }
  return address.port
}

describe("mcp-callback-server", () => {
  beforeEach(async () => {
    // Stop any running server before each test
    await stopCallbackServer().catch(() => {})
  })

  afterEach(async () => {
    // Stop server after each test
    await stopCallbackServer().catch(() => {})
  })

  describe("ensureCallbackServer", () => {
    it("should start the callback server", async () => {
      await ensureCallbackServer()
      assert.strictEqual(isCallbackServerRunning(), true)
    })

    it("should be idempotent", async () => {
      await ensureCallbackServer()
      await ensureCallbackServer()
      await ensureCallbackServer()
      assert.strictEqual(isCallbackServerRunning(), true)
    })

    it("should reserve callback state atomically with the initial bind", async () => {
      await ensureCallbackServer({ oauthState: "reserved-initial-state", reserveState: true })

      await assert.rejects(
        async () => await ensureCallbackServer({ callbackHost: "203.0.113.5" }),
        /cannot be switched while authorizations are pending/
      )

      releaseCallbackServer("reserved-initial-state")
    })

    it("should not switch callback hosts while callback state is reserved", async () => {
      await ensureCallbackServer({ oauthState: "reserved-host-state", reserveState: true })

      await assert.rejects(
        async () => await ensureCallbackServer({ callbackHost: "203.0.113.5" }),
        /cannot be switched while authorizations are pending/
      )

      releaseCallbackServer("reserved-host-state")
    })

    it("should not treat another loopback spelling as a host switch", async () => {
      // All loopback spellings name the same interface and the listener binds
      // the whole set, so none of these may demand a rebind while an
      // authorization is reserved.
      await ensureCallbackServer({ oauthState: "loopback-alias-state", reserveState: true })

      for (const host of ["127.0.0.1", "::1", "localhost"]) {
        await ensureCallbackServer({ callbackHost: host, oauthState: `alias-${host}`, reserveState: true })
        releaseCallbackServer(`alias-${host}`)
      }

      releaseCallbackServer("loopback-alias-state")
    })

    it("should not switch callback paths while callback state is reserved", async () => {
      await ensureCallbackServer({ callbackPath: "/first/callback", oauthState: "reserved-path-state", reserveState: true })

      await assert.rejects(
        async () => await ensureCallbackServer({ callbackPath: "/second/callback" }),
        /cannot be switched while authorizations are pending/
      )
      assert.strictEqual(getOAuthCallbackPath(), "/first/callback")

      releaseCallbackServer("reserved-path-state")
    })

    it("should release reserved callback state when strict binding fails", async () => {
      const port = await getFreePort()
      const releasePort = await squatPort(port)

      try {
        await assert.rejects(
          async () => await ensureCallbackServer({ strictPort: true, port, oauthState: "failed-bind-state", reserveState: true }),
          /already in use/
        )
      } finally {
        await releasePort()
      }

      await ensureCallbackServer({ callbackPath: "/after-failure" })
      await ensureCallbackServer({ callbackPath: "/after-failure-switch" })
      assert.strictEqual(getOAuthCallbackPath(), "/after-failure-switch")
    })

    it("should fail startup when an explicitly configured redirect address cannot be bound", async () => {
      // A configured redirect_uri naming [::1] sends the browser to that
      // literal. If the address is already taken, continuing would leave this
      // adapter advertising a callback that another local process receives.
      const port = await getFreePort()
      const squatter = createServer((_req, res) => {
        res.writeHead(200)
        res.end("not the oauth callback")
      })

      await new Promise<void>((resolve, reject) => {
        squatter.once("error", reject)
        squatter.listen(port, "::1", resolve)
      })

      try {
        await assert.rejects(
          async () => await ensureCallbackServer({
            strictPort: true,
            port,
            callbackHost: "::1",
            oauthState: "occupied-redirect-state",
            reserveState: true,
          }),
          /EADDRINUSE|already in use/
        )
        // Nothing may be left listening, and no state may be reserved.
        assert.strictEqual(getPendingAuthCount(), 0)
        assert.strictEqual(isCallbackServerRunning(), false)
      } finally {
        await new Promise<void>((resolve) => squatter.close(() => resolve()))
      }
    })

    it("should fail startup when an explicit localhost redirect cannot bind every loopback address", async () => {
      // `localhost` may resolve to either family, so binding one address and
      // still advertising `localhost` lets the browser pick the address this
      // process does not hold - and whoever does hold it gets the code.
      const port = await getFreePort()
      const squatter = createServer((_req, res) => {
        res.writeHead(200)
        res.end("not the oauth callback")
      })
      await new Promise<void>((resolve, reject) => {
        squatter.once("error", reject)
        squatter.listen(port, "::1", resolve)
      })

      try {
        await assert.rejects(
          async () => await ensureCallbackServer({
            strictPort: true,
            port,
            callbackHost: "localhost",
            oauthState: "localhost-alias-state",
            reserveState: true,
          }),
          /EADDRINUSE|already in use/
        )
        assert.strictEqual(isCallbackServerRunning(), false)
      } finally {
        await new Promise<void>((resolve) => squatter.close(() => resolve()))
      }
    })

    it("should still tolerate an absent loopback family for the default redirect", async () => {
      // The default redirect is composed from whichever address bound, so an
      // unavailable family must not block startup. This is the counterpart to
      // the two refusal tests above and must not regress into strictness.
      await ensureCallbackServer({ oauthState: "default-tolerates-state", reserveState: true })
      assert.strictEqual(isCallbackServerRunning(), true)
      releaseCallbackServer("default-tolerates-state")
    })

    it("should bind an explicit strict host, port, and custom callback path", async () => {
      const port = await getFreePort()

      await ensureCallbackServer({ strictPort: true, port, callbackHost: "127.0.0.1", callbackPath: "/custom/callback" })

      assert.strictEqual(getOAuthCallbackPort(), port)
      assert.strictEqual(getOAuthCallbackPath(), "/custom/callback")
      assert.strictEqual((await fetch(`http://127.0.0.1:${port}/callback?code=nope&state=custom-state`)).status, 404)

      const callbackPromise = waitForCallback("custom-state")
      const response = await fetch(`http://127.0.0.1:${port}/custom/callback?code=ok&state=custom-state`)
      assert.strictEqual(response.status, 200)
      assert.strictEqual((await callbackPromise).code, "ok")
    })

    it("serves the redirect URI the OAuth provider actually advertises", async () => {
      // Regression guard for the bind/advertise coupling: a listener bound to a
      // different address than the advertised redirect_uri reaches ECONNREFUSED
      // *after* consent, which is far harder to diagnose than a 400 before it.
      // Comparing the advertised host against the getter that produced it would
      // pass even under that drift, so drive the real socket instead.
      await ensureCallbackServer({ oauthState: "advertised-state", reserveState: true })

      const provider = new McpOAuthProvider(
        "advertised",
        "https://mcp.example.com",
        { clientId: "test-client" },
        { onRedirect: async () => {} },
      )
      const advertised = new URL(provider.redirectUrl!)

      const callbackPromise = waitForCallback("advertised-state")
      advertised.searchParams.set("code", "delivered-code")
      advertised.searchParams.set("state", "advertised-state")

      const response = await fetch(advertised)
      assert.strictEqual(response.status, 200)
      assert.strictEqual((await callbackPromise).code, "delivered-code")

      releaseCallbackServer("advertised-state")
    })

    it("accepts every loopback spelling of the redirect host", async () => {
      // RFC 8252 section 7.3 recommends binding both loopback families. A host
      // with only one of them must still authorize, and a redirect_uri naming
      // `localhost` must reach whichever family that resolves to.
      await ensureCallbackServer({ oauthState: "family-state", reserveState: true })
      const port = getOAuthCallbackPort()

      for (const host of ["127.0.0.1", "[::1]", "localhost"]) {
        const probe = new URL(`http://${host}:${port}/callback`)
        probe.searchParams.set("code", "x")
        // An unknown state proves the request reached the handler: it is
        // rejected with 400 rather than throwing ECONNREFUSED.
        probe.searchParams.set("state", "no-such-flow")
        const response = await fetch(probe)
        assert.strictEqual(response.status, 400, `${host} should reach the callback listener`)
      }

      releaseCallbackServer("family-state")
    })

    it("allows a pending default authorization alongside an explicit localhost redirect", async () => {
      // The default host and an explicitly configured `localhost` redirect are
      // the same interface, so neither may need a host switch while the other
      // holds a reservation.
      await ensureCallbackServer({ oauthState: "concurrent-default", reserveState: true })
      await ensureCallbackServer({ callbackHost: "localhost", oauthState: "concurrent-localhost", reserveState: true })

      const port = getOAuthCallbackPort()
      const waiter = waitForCallback("concurrent-localhost")
      const redirect = new URL(`http://localhost:${port}/callback`)
      redirect.searchParams.set("code", "localhost-code")
      redirect.searchParams.set("state", "concurrent-localhost")

      assert.strictEqual((await fetch(redirect)).status, 200)
      assert.strictEqual((await waiter).code, "localhost-code")

      releaseCallbackServer("concurrent-default")
    })

    it("should reject an occupied explicit strict port", async () => {
      const port = await getFreePort()
      const releasePort = await squatPort(port)

      try {
        await assert.rejects(
          async () => await ensureCallbackServer({ strictPort: true, port }),
          /already in use/
        )
      } finally {
        await releasePort()
      }
    })

    it("should use an OS-assigned port when the configured non-strict port is occupied", async () => {
      const configuredPort = getConfiguredOAuthCallbackPort()
      let releasePort: (() => Promise<void>) | undefined
      try {
        releasePort = await squatPort(configuredPort)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EADDRINUSE") return
        throw error
      }

      try {
        await ensureCallbackServer()
        const callbackPort = getOAuthCallbackPort()
        assert.notStrictEqual(callbackPort, configuredPort)

        const state = "occupied-port-state"
        const callbackPromise = waitForCallback(state)
        const response = await fetch(`http://localhost:${callbackPort}/callback?code=ok&state=${state}`)
        assert.strictEqual(response.status, 200)
        assert.strictEqual((await callbackPromise).code, "ok")

        await assert.rejects(
          async () => await ensureCallbackServer({ strictPort: true }),
          /already in use/
        )
      } finally {
        await releasePort?.()
      }
    })
  })

  describe("waitForCallback / callback handling", () => {
    it("should resolve with code on successful callback", async () => {
      await ensureCallbackServer()

      const state = "test-state-123"
      const expectedCode = "auth-code-abc"

      // Start waiting for callback
      const callbackPromise = waitForCallback(state)

      // Simulate callback by making HTTP request
      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?code=${expectedCode}&state=${state}`
      )

      // Should get HTML success response
      assert.strictEqual(response.status, 200)
      const html = await response.text()
      assert.ok(html.includes("Authorization Successful"))

      // Callback promise should resolve
      const result = await callbackPromise
      assert.strictEqual(result.code, expectedCode)
      assert.strictEqual(result.iss, undefined)
    })

    it("should propagate the RFC 9207 iss parameter when present", async () => {
      await ensureCallbackServer()

      const state = "test-state-iss"
      const expectedCode = "auth-code-iss"
      const expectedIss = "https://auth.example.com"

      const callbackPromise = waitForCallback(state)

      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?code=${expectedCode}&state=${state}&iss=${encodeURIComponent(expectedIss)}`
      )
      assert.strictEqual(response.status, 200)
      await response.text()

      const result = await callbackPromise
      assert.strictEqual(result.code, expectedCode)
      assert.strictEqual(result.iss, expectedIss)
    })

    it("should reject on error parameter", async () => {
      await ensureCallbackServer()

      const state = "test-state-error"
      const errorMsg = "access_denied"

      const callbackPromise = waitForCallback(state)
      const rejection = assert.rejects(callbackPromise, /access_denied/)

      // Simulate error callback
      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?error=${errorMsg}&state=${state}`
      )

      assert.strictEqual(response.status, 200)
      const html = await response.text()
      assert.ok(html.includes("Authorization Failed"))

      // Callback promise should reject
      await rejection
    })

    it("should escape provider-controlled OAuth error details", async () => {
      await ensureCallbackServer()

      const state = "test-state-error-escaping"
      const callbackPromise = waitForCallback(state)
      const rejection = assert.rejects(callbackPromise, /<script>alert\("x"\)<\/script>&reason=bad/)
      const callbackPort = getOAuthCallbackPort()
      const description = `<script>alert("x")</script>&reason=bad`
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?error=access_denied&error_description=${encodeURIComponent(description)}&state=${state}`
      )

      assert.strictEqual(response.status, 200)
      const html = await response.text()
      assert.ok(!html.includes("<script>"))
      assert.ok(html.includes("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;reason=bad"))
      await rejection
    })

    it("should not reflect OAuth error details for invalid state", async () => {
      await ensureCallbackServer()

      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?error=access_denied&error_description=${encodeURIComponent("<script>bad()</script>")}&state=invalid-state`
      )

      assert.strictEqual(response.status, 400)
      const html = await response.text()
      assert.ok(html.includes("Invalid or expired state parameter"))
      assert.ok(!html.includes("<script>"))
      assert.ok(!html.includes("bad()"))
    })

    it("should return 400 for missing state", async () => {
      await ensureCallbackServer()

      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?code=abc123`
      )

      assert.strictEqual(response.status, 400)
      const html = await response.text()
      assert.ok(html.includes("Missing required state parameter"))
    })

    it("should return 400 for invalid state", async () => {
      await ensureCallbackServer()

      // Register a different state
      const pendingCallback = waitForCallback("valid-state")

      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?code=abc123&state=invalid-state`
      )

      assert.strictEqual(response.status, 400)
      const html = await response.text()
      assert.ok(html.includes("Invalid or expired state parameter"))

      cancelPendingCallback("valid-state")
      await assert.rejects(pendingCallback, /Authorization cancelled/)
    })

    it("should return 400 for missing code", async () => {
      await ensureCallbackServer()

      const state = "test-state-no-code"
      const pendingCallback = waitForCallback(state)

      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/callback?state=${state}`
      )

      assert.strictEqual(response.status, 400)
      const html = await response.text()
      assert.ok(html.includes("No authorization code provided"))

      cancelPendingCallback(state)
      await assert.rejects(pendingCallback, /Authorization cancelled/)
    })

    it("should not switch callback paths while callbacks are pending", async () => {
      await ensureCallbackServer({ callbackPath: "/first/callback" })

      const state = "pending-path-state"
      const callbackPromise = waitForCallback(state)

      await assert.rejects(
        async () => await ensureCallbackServer({ callbackPath: "/second/callback" }),
        /cannot be switched while authorizations are pending/
      )
      assert.strictEqual(getOAuthCallbackPath(), "/first/callback")

      cancelPendingCallback(state)
      await assert.rejects(callbackPromise, /Authorization cancelled/)
    })

    it("should return 404 for wrong path", async () => {
      await ensureCallbackServer()

      const callbackPort = getOAuthCallbackPort()
      const response = await fetch(
        `http://localhost:${callbackPort}/wrong/path`
      )

      assert.strictEqual(response.status, 404)
    })
  })

  describe("cancelPendingCallback", () => {
    it("should reject pending callback", async () => {
      await ensureCallbackServer()

      const state = "test-state-cancel"
      const callbackPromise = waitForCallback(state)

      cancelPendingCallback(state)

      await assert.rejects(callbackPromise, /Authorization cancelled/)
    })
  })

  describe("stopCallbackServer", () => {
    it("should stop the server", async () => {
      await ensureCallbackServer()
      assert.strictEqual(isCallbackServerRunning(), true)

      await stopCallbackServer()
      assert.strictEqual(isCallbackServerRunning(), false)
    })

    it("should reject all pending callbacks", async () => {
      await ensureCallbackServer()

      const state1 = "state-1"
      const state2 = "state-2"

      const promise1 = waitForCallback(state1)
      const promise2 = waitForCallback(state2)

      await stopCallbackServer()

      await assert.rejects(promise1, /OAuth callback server stopped/)
      await assert.rejects(promise2, /OAuth callback server stopped/)
    })
  })

  describe("getPendingAuthCount", () => {
    it("should return 0 when no pending auths", async () => {
      await ensureCallbackServer()
      assert.strictEqual(getPendingAuthCount(), 0)
    })

    it("should return count of pending auths", async () => {
      await ensureCallbackServer()

      const promise1 = waitForCallback("state-1")
      assert.strictEqual(getPendingAuthCount(), 1)

      const promise2 = waitForCallback("state-2")
      assert.strictEqual(getPendingAuthCount(), 2)

      const promise3 = waitForCallback("state-3")
      assert.strictEqual(getPendingAuthCount(), 3)

      cancelPendingCallback("state-1")
      cancelPendingCallback("state-2")
      cancelPendingCallback("state-3")
      await assert.rejects(promise1, /Authorization cancelled/)
      await assert.rejects(promise2, /Authorization cancelled/)
      await assert.rejects(promise3, /Authorization cancelled/)
    })
  })
})

describe("callback page branding", () => {
  const originalPackageDir = process.env.PI_PACKAGE_DIR
  const packageDirs: string[] = []

  function brandedPackageDir(name?: string): string {
    const dir = mkdtempSync(join(tmpdir(), "mcp-callback-brand-"))
    packageDirs.push(dir)
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify(name ? { name: "pi", piConfig: { name } } : { name: "pi" }),
    )
    return dir
  }

  /** Drive a real callback request and read the HTML the browser would get. */
  async function fetchCallbackHtml(): Promise<string> {
    await ensureCallbackServer()
    const state = "brandingteststate"
    const pending = waitForCallback(state)
    const url = `http://localhost:${getOAuthCallbackPort()}${getOAuthCallbackPath()}?state=${state}&code=abc123`
    const response = await fetch(url)
    const html = await response.text()
    await pending
    return html
  }

  afterEach(async () => {
    if (originalPackageDir === undefined) delete process.env.PI_PACKAGE_DIR
    else process.env.PI_PACKAGE_DIR = originalPackageDir
    for (const dir of packageDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
    await stopCallbackServer()
  })

  it("names the host app rather than hardcoding Pi", async () => {
    process.env.PI_PACKAGE_DIR = brandedPackageDir("arc")
    const html = await fetchCallbackHtml()
    assert.match(html, /return to <span class="app">arc<\/span>/)
    assert.match(html, /<title>arc — Authorization Successful<\/title>/)
    assert.doesNotMatch(html, /return to <span class="app">Pi<\/span>/)
  })

  it("falls back to pi when the host is not rebranded", async () => {
    process.env.PI_PACKAGE_DIR = brandedPackageDir()
    const html = await fetchCallbackHtml()
    assert.match(html, /return to <span class="app">pi<\/span>/)
  })

  it("serves a self-contained page — no external assets", async () => {
    delete process.env.PI_PACKAGE_DIR
    const html = await fetchCallbackHtml()
    assert.doesNotMatch(html, /https?:\/\//)
  })
})
