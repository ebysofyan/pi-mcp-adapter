import { beforeEach, describe, expect, it, vi } from "vitest";

type MockServer = {
  once: ReturnType<typeof vi.fn>;
  listen: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  unref: ReturnType<typeof vi.fn>;
  address: ReturnType<typeof vi.fn>;
  handlers: Map<string, (error?: NodeJS.ErrnoException) => void>;
};

const mocks = vi.hoisted(() => {
  const state = {
    configuredPort: 4337,
    activePort: 4337,
    callbackPath: "/callback",
    callbackHost: "127.0.0.1",
  };

  const runtime = {
    assignedPort: 4338,
    listenImpl: (
      _server: MockServer,
      _port: number,
      _host: string,
      onListen: () => void,
      _handlers: Map<string, (error?: NodeJS.ErrnoException) => void>
    ) => {
      onListen();
    },
    servers: [] as MockServer[],
    // The callback listener binds the whole loopback set, so a single bind can
    // involve more than one listen() call. Tests that gate the bind collect the
    // pending callbacks here and release them together.
    pendingListens: [] as (() => void)[],
  };

  /**
   * Release every listen() that has not completed yet. A single bind issues one
   * listen per loopback address, and the next is only queued once the previous
   * resolves, so this drains progressively instead of flushing once.
   */
  const flushListens = async () => {
    for (let round = 0; round < 20; round += 1) {
      const queued = runtime.pendingListens.splice(0, runtime.pendingListens.length);
      if (queued.length > 0) {
        for (const onListen of queued) onListen();
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
      if (queued.length === 0 && runtime.pendingListens.length === 0) return;
    }
  };

  /** Collect listen() callbacks instead of completing them, for gated binds. */
  const deferListens = () => {
    runtime.listenImpl = (_server, _port, _host, onListen) => {
      runtime.pendingListens.push(onListen);
    };
  };

  /** Complete every listen() immediately (the default). */
  const resumeListens = () => {
    runtime.listenImpl = (_server, _port, _host, onListen) => {
      onListen();
    };
  };

  const createServer = vi.fn((_handler: unknown) => {
    const handlers = new Map<string, (error?: NodeJS.ErrnoException) => void>();
    const server: MockServer = {
      handlers,
      once: vi.fn((event: string, handler: (error?: NodeJS.ErrnoException) => void) => {
        handlers.set(event, handler);
        return server;
      }),
      listen: vi.fn((port: number, host: string, onListen: () => void) => {
        runtime.listenImpl(server, port, host, onListen, handlers);
      }),
      close: vi.fn((cb?: () => void) => cb?.()),
      unref: vi.fn(),
      address: vi.fn(() => ({ address: "127.0.0.1", family: "IPv4", port: runtime.assignedPort })),
    };

    runtime.servers.push(server);
    return server;
  });

  return {
    state,
    runtime,
    createServer,
    flushListens,
    deferListens,
    resumeListens,
    getConfiguredOAuthCallbackPort: vi.fn(() => state.configuredPort),
    getOAuthCallbackPort: vi.fn(() => state.activePort),
    getOAuthCallbackPath: vi.fn(() => state.callbackPath),
    getOAuthCallbackHost: vi.fn(() => state.callbackHost),
    setOAuthCallbackHost: vi.fn((host: string) => {
      state.callbackHost = host;
    }),
    setOAuthCallbackPath: vi.fn((path: string) => {
      state.callbackPath = path.startsWith("/") ? path : `/${path}`;
    }),
    setOAuthCallbackPort: vi.fn((port: number) => {
      state.activePort = port;
    }),
  };
});

vi.mock("http", () => ({
  createServer: mocks.createServer,
}));

vi.mock("../mcp-oauth-provider.ts", () => ({
  DEFAULT_OAUTH_CALLBACK_HOST: "127.0.0.1",
  DEFAULT_OAUTH_CALLBACK_PATH: "/callback",
  getConfiguredOAuthCallbackPort: mocks.getConfiguredOAuthCallbackPort,
  getOAuthCallbackPath: mocks.getOAuthCallbackPath,
  getOAuthCallbackPort: mocks.getOAuthCallbackPort,
  getOAuthCallbackHost: mocks.getOAuthCallbackHost,
  setOAuthCallbackHost: mocks.setOAuthCallbackHost,
  setOAuthCallbackPath: mocks.setOAuthCallbackPath,
  setOAuthCallbackPort: mocks.setOAuthCallbackPort,
}));

describe("mcp-callback-server", () => {
  beforeEach(() => {
    vi.resetModules();
    mocks.state.configuredPort = 4337;
    mocks.state.activePort = 4337;
    mocks.state.callbackPath = "/callback";
    mocks.state.callbackHost = "127.0.0.1";
    mocks.runtime.assignedPort = 4338;
    mocks.runtime.servers = [];
    mocks.runtime.pendingListens = [];
    mocks.resumeListens();
    mocks.createServer.mockClear();
    mocks.getConfiguredOAuthCallbackPort.mockClear();
    mocks.getOAuthCallbackPath.mockClear();
    mocks.getOAuthCallbackPort.mockClear();
    mocks.getOAuthCallbackHost.mockClear();
    mocks.setOAuthCallbackHost.mockClear();
    mocks.setOAuthCallbackPath.mockClear();
    mocks.setOAuthCallbackPort.mockClear();
  });

  it("binds the loopback IP literal on an OS-assigned port and unrefs after a successful non-strict bind", async () => {
    const { ensureCallbackServer } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer();

    expect(mocks.runtime.servers[0]?.listen).toHaveBeenCalledWith(0, "127.0.0.1", expect.any(Function));
    expect(mocks.runtime.servers[0]?.unref).toHaveBeenCalledTimes(1);
    expect(mocks.state.activePort).toBe(4338);
  });

  it("binds the configured port exactly in strict mode", async () => {
    const { ensureCallbackServer } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer({ strictPort: true });

    expect(mocks.runtime.servers[0]?.listen).toHaveBeenCalledWith(4337, "127.0.0.1", expect.any(Function));
    expect(mocks.runtime.servers[0]?.listen).not.toHaveBeenCalledWith(0, "127.0.0.1", expect.any(Function));
    expect(mocks.state.activePort).toBe(4337);
  });

  it("binds an explicit loopback host and port exactly in strict mode", async () => {
    const { ensureCallbackServer } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer({ strictPort: true, port: 3118, callbackHost: "127.0.0.1", callbackPath: "/custom/callback" });

    expect(mocks.runtime.servers[0]?.listen).toHaveBeenCalledWith(3118, "127.0.0.1", expect.any(Function));
    expect(mocks.runtime.servers[0]?.listen).not.toHaveBeenCalledWith(0, "127.0.0.1", expect.any(Function));
    expect(mocks.state.activePort).toBe(3118);
    expect(mocks.state.callbackPath).toBe("/custom/callback");
  });

  it("does not unref when bind fails", async () => {
    mocks.runtime.listenImpl = (_server, _port, _host, _onListen, handlers) => {
      Promise.resolve().then(() => {
        handlers.get("error")?.(Object.assign(new Error("EADDRINUSE"), { code: "EADDRINUSE" }));
      });
    };

    const { ensureCallbackServer } = await import("../mcp-callback-server.ts");

    await expect(ensureCallbackServer({ strictPort: true })).rejects.toThrow(/already in use/);
    expect(mocks.runtime.servers[0]?.unref).not.toHaveBeenCalled();
  });

  it("serializes concurrent callback server startup", async () => {
    mocks.deferListens();

    const { ensureCallbackServer } = await import("../mcp-callback-server.ts");

    const first = ensureCallbackServer();
    const second = ensureCallbackServer();
    expect(mocks.runtime.servers).toHaveLength(1);

    await mocks.flushListens();
    await Promise.all([first, second]);

    // One listener per loopback address, sharing the assigned port.
    expect(mocks.runtime.servers).toHaveLength(2);
    expect(mocks.runtime.servers[0]?.unref).toHaveBeenCalledTimes(1);
    expect(mocks.runtime.servers[1]?.unref).toHaveBeenCalledTimes(1);
    expect(mocks.state.activePort).toBe(4338);
  });

  it("waits for an in-progress bind before stopping and permits later reuse", async () => {
    mocks.deferListens();

    const { ensureCallbackServer, stopCallbackServer, isCallbackServerRunning } = await import("../mcp-callback-server.ts");
    const starting = ensureCallbackServer();
    await Promise.resolve();
    const stopping = stopCallbackServer();
    await mocks.flushListens();

    await Promise.all([starting, stopping]);
    expect(isCallbackServerRunning()).toBe(false);
    expect(mocks.runtime.servers[0]?.close).toHaveBeenCalledTimes(1);
    expect(mocks.runtime.servers[1]?.close).toHaveBeenCalledTimes(1);

    mocks.resumeListens();
    await ensureCallbackServer();
    expect(isCallbackServerRunning()).toBe(true);
    expect(mocks.runtime.servers).toHaveLength(4);
  });

  it("rejects callback startup queued before shutdown", async () => {
    mocks.deferListens();

    const { ensureCallbackServer, stopCallbackServer, isCallbackServerRunning } = await import("../mcp-callback-server.ts");
    const starting = ensureCallbackServer();
    await Promise.resolve();
    const queued = ensureCallbackServer({ strictPort: true });
    const queuedResult = expect(queued).rejects.toThrow("OAuth callback server stopped");
    const stopping = stopCallbackServer();
    await mocks.flushListens();

    await expect(starting).resolves.toBeUndefined();
    await queuedResult;
    await expect(stopping).resolves.toBeUndefined();
    expect(isCallbackServerRunning()).toBe(false);
    expect(mocks.runtime.servers).toHaveLength(2);
    expect(mocks.runtime.servers[0]?.close).toHaveBeenCalledTimes(1);
    expect(mocks.runtime.servers[1]?.close).toHaveBeenCalledTimes(1);
  });

  it("rejects callback startup issued while shutdown is closing the server", async () => {
    const { ensureCallbackServer, stopCallbackServer, isCallbackServerRunning } = await import("../mcp-callback-server.ts");
    await ensureCallbackServer();
    let finishClose: (() => void) | undefined;
    mocks.runtime.servers[0].close.mockImplementation((callback?: () => void) => {
      finishClose = callback;
    });

    const stopping = stopCallbackServer();
    await expect(ensureCallbackServer({ strictPort: true, reserveState: true, oauthState: "stale" }))
      .rejects.toThrow("OAuth callback server stopped");
    expect(mocks.runtime.servers).toHaveLength(2);

    finishClose?.();
    await expect(stopping).resolves.toBeUndefined();
    expect(isCallbackServerRunning()).toBe(false);

    await ensureCallbackServer();
    expect(isCallbackServerRunning()).toBe(true);
    expect(mocks.runtime.servers).toHaveLength(4);
  });

  it("waits for idle shutdown before starting a new callback server", async () => {
    const {
      ensureCallbackServer,
      isCallbackServerRunning,
      stopCallbackServerIfIdle,
    } = await import("../mcp-callback-server.ts");
    await ensureCallbackServer();
    let finishClose: (() => void) | undefined;
    mocks.runtime.servers[0].close.mockImplementation((callback?: () => void) => {
      finishClose = callback;
    });

    const stopping = stopCallbackServerIfIdle();
    const restarting = ensureCallbackServer({ reserveState: true, oauthState: "new-flow" });
    expect(mocks.runtime.servers).toHaveLength(2);

    finishClose?.();
    await stopping;
    await restarting;

    expect(isCallbackServerRunning()).toBe(true);
    expect(mocks.runtime.servers).toHaveLength(4);
    await expect(ensureCallbackServer({ callbackPath: "/other/callback" }))
      .rejects.toThrow(/cannot be switched while authorizations are pending/);
  });

  it("forced shutdown revokes a restart waiting on idle shutdown", async () => {
    const {
      ensureCallbackServer,
      isCallbackServerRunning,
      stopCallbackServer,
      stopCallbackServerIfIdle,
    } = await import("../mcp-callback-server.ts");
    await ensureCallbackServer();
    let finishClose: (() => void) | undefined;
    mocks.runtime.servers[0].close.mockImplementation((callback?: () => void) => {
      finishClose = callback;
    });

    const idleStopping = stopCallbackServerIfIdle();
    const restarting = ensureCallbackServer({ reserveState: true, oauthState: "stopped-flow" });
    const restartResult = expect(restarting).rejects.toThrow("OAuth callback server stopped");
    const forcedStopping = stopCallbackServer();

    finishClose?.();
    await Promise.all([idleStopping, forcedStopping]);
    await restartResult;

    expect(isCallbackServerRunning()).toBe(false);
    expect(mocks.runtime.servers).toHaveLength(2);
  });

  it("does not stop while a concurrent bind is reserving callback state", async () => {
    const {
      ensureCallbackServer,
      isCallbackServerRunning,
      stopCallbackServerIfIdle,
    } = await import("../mcp-callback-server.ts");
    await ensureCallbackServer();

    mocks.deferListens();
    const rebinding = ensureCallbackServer({
      strictPort: true,
      reserveState: true,
      oauthState: "concurrent-state",
    });

    await stopCallbackServerIfIdle();
    await mocks.flushListens();
    await rebinding;

    expect(isCallbackServerRunning()).toBe(true);
    // The rebind candidates (2 and 3) must still be open.
    expect(mocks.runtime.servers[2]?.close).not.toHaveBeenCalled();
    expect(mocks.runtime.servers[3]?.close).not.toHaveBeenCalled();
    await expect(ensureCallbackServer({ callbackPath: "/other/callback" }))
      .rejects.toThrow(/cannot be switched while authorizations are pending/);
  });

  it("rebinds to the configured port when strict mode is requested", async () => {
    const { ensureCallbackServer } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer();
    expect(mocks.state.activePort).toBe(4338);

    await ensureCallbackServer({ strictPort: true });

    expect(mocks.runtime.servers[0]?.close).toHaveBeenCalledTimes(1);
    expect(mocks.runtime.servers[1]?.close).toHaveBeenCalledTimes(1);
    expect(mocks.runtime.servers[2]?.listen).toHaveBeenCalledWith(4337, "127.0.0.1", expect.any(Function));
    expect(mocks.runtime.servers[3]?.listen).toHaveBeenCalledWith(4337, "::1", expect.any(Function));
    expect(mocks.state.activePort).toBe(4337);
  });

  it("keeps the existing callback server when strict rebind fails", async () => {
    const { ensureCallbackServer, isCallbackServerRunning } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer();
    expect(mocks.state.activePort).toBe(4338);

    mocks.runtime.listenImpl = (_server, port, _host, onListen, handlers) => {
      if (port === mocks.state.configuredPort) {
        Promise.resolve().then(() => {
          handlers.get("error")?.(Object.assign(new Error("EADDRINUSE"), { code: "EADDRINUSE" }));
        });
        return;
      }

      onListen();
    };

    await expect(ensureCallbackServer({ strictPort: true })).rejects.toThrow(/already in use/);

    expect(isCallbackServerRunning()).toBe(true);
    expect(mocks.runtime.servers[0]?.close).not.toHaveBeenCalled();
    expect(mocks.state.activePort).toBe(4338);
  });

  it("does not switch ports in strict mode while an authorization URL can reference the active port", async () => {
    const {
      ensureCallbackServer,
      reserveCallbackServer,
      releaseCallbackServer,
    } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer();
    reserveCallbackServer("reserved-state");

    await expect(ensureCallbackServer({ strictPort: true })).rejects.toThrow(/cannot be switched while authorizations are pending/);
    expect(mocks.runtime.servers).toHaveLength(2);

    releaseCallbackServer("reserved-state");
  });

  it("reserves callback state inside ensureCallbackServer before releasing the startup lock", async () => {
    const {
      ensureCallbackServer,
      releaseCallbackServer,
    } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer({ oauthState: "atomic-reserved-state", reserveState: true });

    await expect(ensureCallbackServer({ strictPort: true })).rejects.toThrow(/cannot be switched while authorizations are pending/);
    expect(mocks.runtime.servers).toHaveLength(2);

    releaseCallbackServer("atomic-reserved-state");
  });

  it("does not switch host or path while callback state reserved by ensureCallbackServer", async () => {
    const {
      ensureCallbackServer,
      releaseCallbackServer,
    } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer({ callbackPath: "/first/callback", oauthState: "reserved-endpoint-state", reserveState: true });

    await expect(ensureCallbackServer({ callbackHost: "203.0.113.5" })).rejects.toThrow(/cannot be switched while authorizations are pending/);
    await expect(ensureCallbackServer({ callbackPath: "/second/callback" })).rejects.toThrow(/cannot be switched while authorizations are pending/);
    expect(mocks.runtime.servers).toHaveLength(2);
    expect(mocks.state.callbackPath).toBe("/first/callback");

    releaseCallbackServer("reserved-endpoint-state");
  });

  it("does not switch ports in strict mode while callbacks are pending", async () => {
    const {
      ensureCallbackServer,
      waitForCallback,
      cancelPendingCallback,
    } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer();
    const pending = waitForCallback("pending-state");

    await expect(ensureCallbackServer({ strictPort: true })).rejects.toThrow(/cannot be switched while authorizations are pending/);
    expect(mocks.runtime.servers).toHaveLength(2);

    cancelPendingCallback("pending-state");
    await expect(pending).rejects.toThrow(/Authorization cancelled/);
  });

  it("stops only when no pending or reserved auth state remains", async () => {
    const {
      ensureCallbackServer,
      reserveCallbackServer,
      releaseCallbackServer,
      waitForCallback,
      cancelPendingCallback,
      isCallbackServerRunning,
      stopCallbackServerIfIdle,
    } = await import("../mcp-callback-server.ts");

    await ensureCallbackServer();
    reserveCallbackServer("reserved-state");
    await stopCallbackServerIfIdle();
    expect(isCallbackServerRunning()).toBe(true);

    releaseCallbackServer("reserved-state");
    const pending = waitForCallback("pending-state");
    await stopCallbackServerIfIdle();
    expect(isCallbackServerRunning()).toBe(true);
    cancelPendingCallback("pending-state");
    await expect(pending).rejects.toThrow(/Authorization cancelled/);
    await stopCallbackServerIfIdle();
    expect(isCallbackServerRunning()).toBe(false);
  });
});
