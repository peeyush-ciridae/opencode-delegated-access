import { describe, expect, it, vi } from "vitest"
const bridge = vi.hoisted(() => ({ client: undefined as any, permission: vi.fn(), event: vi.fn(), system: vi.fn() }))
vi.mock("./index.ts", () => ({
  default: async ({ client }: any) => {
    bridge.client = client
    return { "permission.ask": bridge.permission, event: bridge.event, "experimental.chat.system.transform": bridge.system }
  },
}))
import DelegatedAccessV2 from "./v2.ts"

describe("OpenCode v2 plugin entry", () => {
  it("exports a stable native v2 plugin definition", () => {
    expect(DelegatedAccessV2.id).toBe("opencode-delegated-access")
    expect(typeof DelegatedAccessV2.setup).toBe("function")
  })

  it("uses a disposable session with the classifier model and isolated policy, then removes it", async () => {
    const hooks = new Map<string, any>()
    const session = {
      create: vi.fn(async () => ({ id: "classifier" })),
      switchModel: vi.fn(async () => {}),
      generate: vi.fn(async () => ({ text: 'VERDICT: SAFE\nREASON: read only' })),
      remove: vi.fn(async () => {}),
      hook: async (name: string, callback: any) => { hooks.set(name, callback) },
    }
    const context: any = {
      options: {}, location: { directory: "/project", project: { directory: "/project" } },
      permission: { hook: async () => {} }, session,
      generate: { text: vi.fn(() => { throw new Error("must not use stateless generation") }) },
      event: { subscribe: async function* () {} },
    }
    await DelegatedAccessV2.setup(context)
    const created = await bridge.client.session.create({ body: { parentID: "working", title: "classifier" } })
    expect(session.create).toHaveBeenCalledWith({ title: "classifier" })
    const response = await bridge.client.session.prompt({
      path: { id: created.data.id },
      body: { model: { providerID: "anthropic", modelID: "claude-haiku-5-5#none" },
        system: "classifier policy", parts: [{ type: "text", text: "command and five human messages" }] },
    })
    expect(session.switchModel).toHaveBeenCalledWith({ sessionID: "classifier", model: {
      providerID: "anthropic", id: "claude-haiku-5-5", variant: "none",
    } })
    expect(session.generate).toHaveBeenCalledWith({ sessionID: "classifier", prompt: "command and five human messages" })
    expect(response.data.parts).toEqual([{ type: "text", text: 'VERDICT: SAFE\nREASON: read only' }])
    bridge.system.mockImplementationOnce((_input, output) => { output.system = ["classifier policy"] })
    const event = { sessionID: "classifier", model: {}, system: [{ type: "text", text: "global agent instructions" }] }
    await hooks.get("generate")(event)
    expect(event.system).toEqual([{ type: "text", text: "classifier policy" }])
    await bridge.client.session.delete({ path: { id: created.data.id } })
    expect(session.remove).toHaveBeenCalledWith({ sessionID: "classifier" })
    expect(context.generate.text).not.toHaveBeenCalled()
  })

  it("classifies shell asks without weakening allows or denies or dropping command segments", async () => {
    let evaluate: any
    const context: any = {
      options: { contextMessageCount: 3 },
      location: { directory: "/project", project: { directory: "/project" } },
      permission: { hook: async (_: string, callback: any) => { evaluate = callback } },
      session: { hook: async () => {}, context: async () => [
        { id: "1", type: "user", text: "human", agent: "build" },
        { id: "2", type: "synthetic", text: "agent dispatch", agent: "build" },
        { id: "3", type: "system", text: "instructions", agent: "build" },
      ] },
      event: { subscribe: async function* () {} },
    }
    await DelegatedAccessV2.setup(context)
    bridge.permission.mockClear()
    bridge.permission.mockImplementation(async (_permission, output) => { output.status = "allow" })
    for (const effect of ["allow", "deny"]) {
      const event = { action: "shell", effect, sessionID: "root", resources: ["pwd"] }
      await evaluate(event)
      expect(event.effect).toBe(effect)
    }
    expect(bridge.permission).not.toHaveBeenCalled()
    const event = { action: "shell", effect: "ask", sessionID: "root", resources: ["pwd", "ls"] }
    await evaluate(event)
    expect(event.effect).toBe("allow")
    expect(bridge.permission.mock.calls[0]?.[0]).toMatchObject({ permission: "bash", patterns: ["pwd", "ls"] })
    const messages = await bridge.client.session.messages({ path: { id: "root" } })
    expect(messages.data.map((entry: any) => entry.parts[0].text)).toEqual(["human"])
  })

  it("forwards a human reply to the legacy plugin under the legacy permission ID", async () => {
    let evaluate: any
    let releaseEvents!: () => void
    const evaluated = new Promise<void>((resolve) => { releaseEvents = resolve })
    const request = { sessionID: "root", action: "shell", resources: ["rm -rf build"], source: { type: "tool", messageID: "msg", id: "call" } }
    const context: any = {
      options: {},
      location: { directory: "/project", project: { directory: "/project" } },
      permission: { hook: async (_: string, callback: any) => { evaluate = callback } },
      session: { hook: async () => {}, context: async () => [] },
      event: { subscribe: async function* () {
        await evaluated
        yield { type: "permission.asked", data: { id: "per_1", ...request } }
        yield { type: "permission.replied", data: { sessionID: "root", requestID: "per_1", reply: "reject" } }
      } },
    }
    bridge.permission.mockReset()
    bridge.event.mockReset()
    const cleanup = await DelegatedAccessV2.setup(context)
    await evaluate({ ...request, effect: "ask" })
    releaseEvents()
    await vi.waitFor(() => expect(bridge.event).toHaveBeenCalled())
    const legacyID = bridge.permission.mock.calls[0]?.[0].id
    expect(bridge.event.mock.calls[0]?.[0]).toEqual({
      event: { type: "permission.replied", properties: { sessionID: "root", permissionID: legacyID, response: "reject" } },
    })
    await (cleanup as any)?.()
  })
})
