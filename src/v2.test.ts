import { describe, expect, it, vi } from "vitest"
const bridge = vi.hoisted(() => ({ client: undefined as any, permission: vi.fn(), event: vi.fn() }))
vi.mock("./index.ts", () => ({
  default: async ({ client }: any) => {
    bridge.client = client
    return { "permission.ask": bridge.permission, event: bridge.event }
  },
}))
import DelegatedAccessV2 from "./v2.ts"

describe("OpenCode v2 plugin entry", () => {
  it("exports a stable native v2 plugin definition", () => {
    expect(DelegatedAccessV2.id).toBe("opencode-delegated-access")
    expect(typeof DelegatedAccessV2.setup).toBe("function")
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
