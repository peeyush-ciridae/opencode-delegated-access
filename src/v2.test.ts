import { describe, expect, it, vi } from "vitest"
const bridge = vi.hoisted(() => ({ client: undefined as any, permission: vi.fn(), event: vi.fn() }))
vi.mock("./index.ts", () => ({
  default: async ({ client }: any) => {
    bridge.client = client
    return { "permission.ask": bridge.permission, event: bridge.event }
  },
}))
import DelegatedAccessV2, { classifyWithJev } from "./v2.ts"
import { classifyCloudAccess } from "./read-only-requests.ts"

describe("Jev classifier", () => {
  it("is SAFE only at or above the threshold and fails without a key", async () => {
    vi.stubEnv("TYPESAFE_API_KEY", "test-key")
    for (const [noul, verdict] of [[0.9, "SAFE"], [0.89, "RISKY"]] as const) {
      vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ answers: { safe: { type: "noul", noul } } }))))
      expect(await classifyWithJev("jev-latest", "policy", "<command>ls</command>")).toMatch(new RegExp(`^VERDICT: ${verdict}\n`))
    }
    vi.stubEnv("TYPESAFE_API_KEY", "")
    await expect(classifyWithJev("jev-latest", "policy", "x")).rejects.toThrow("TYPESAFE_API_KEY")
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
  })
})

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

  it("classifies cloud MCP asks from the pending tool input and keeps unknown or oversized calls as asks", async () => {
    let evaluate: any
    const code = 'await tools.gcloud.run_gcloud_command({ args: ["run", "services", "delete", "svc"] })'
    const context: any = {
      options: {},
      location: { directory: "/project", project: { directory: "/project" } },
      permission: { hook: async (_: string, callback: any) => { evaluate = callback } },
      session: { hook: async () => {}, context: async () => [
        { id: "msg", type: "assistant", content: [
          { type: "tool", id: "call", name: "execute", state: { input: { code } } },
          { type: "tool", id: "huge", name: "execute", state: { input: { code: "x".repeat(9000) } } },
        ] },
      ] },
      event: { subscribe: async function* () {} },
    }
    await DelegatedAccessV2.setup(context)
    bridge.permission.mockClear()
    bridge.permission.mockImplementation(async (_permission, output) => { output.status = "allow" })

    const cloud = { action: "gcloud_run_gcloud_command", effect: "ask", sessionID: "root", resources: ["*"], source: { messageID: "msg", id: "call" } }
    await evaluate(cloud)
    expect(cloud.effect).toBe("allow")
    expect(bridge.permission.mock.calls[0]?.[0]).toMatchObject({ permission: "cloud_tool" })
    expect(bridge.permission.mock.calls[0]?.[0].patterns[0]).toContain(code)

    for (const id of ["missing", "huge"]) {
      const event = { action: "aws_aws___run_script", effect: "ask", sessionID: "root", resources: ["*"], source: { messageID: "msg", id } }
      await evaluate(event)
      expect(event.effect).toBe("ask")
    }
    const other = { action: "linear_save_issue", effect: "ask", sessionID: "root", resources: ["*"], source: { messageID: "msg", id: "call" } }
    await evaluate(other)
    expect(other.effect).toBe("ask")
    expect(bridge.permission).toHaveBeenCalledTimes(1)
  })

  it("approves read-only cloud calls and outside-project file reads without the classifier", async () => {
    let evaluate: any
    const context: any = {
      options: {},
      location: { directory: "/project", project: { directory: "/project" } },
      permission: { hook: async (_: string, callback: any) => { evaluate = callback } },
      session: { hook: async () => {}, context: async () => [
        { id: "msg", type: "assistant", content: [
          { type: "tool", id: "cloud-read", name: "execute", state: { input: { code: 'await tools.gcloud.run_gcloud_command({ args: ["logging", "read", "x"] })' } } },
          { type: "tool", id: "file-read", name: "read", state: { input: { filePath: "/elsewhere/a.ts" } } },
          { type: "tool", id: "file-edit", name: "edit", state: { input: { filePath: "/elsewhere/a.ts" } } },
        ] },
      ] },
      event: { subscribe: async function* () {} },
    }
    await DelegatedAccessV2.setup(context)
    bridge.permission.mockClear()
    bridge.permission.mockImplementation(async (_permission, output) => { output.status = "ask" })

    const cloud = { action: "gcloud_run_gcloud_command", effect: "ask", sessionID: "root", resources: ["*"], source: { messageID: "msg", id: "cloud-read" } }
    await evaluate(cloud)
    expect(cloud.effect).toBe("allow")

    const read = { action: "external_directory", effect: "ask", sessionID: "root", resources: ["/elsewhere/*"], source: { messageID: "msg", id: "file-read" } }
    await evaluate(read)
    expect(read.effect).toBe("allow")
    expect(bridge.permission).not.toHaveBeenCalled()

    const edit = { action: "external_directory", effect: "ask", sessionID: "root", resources: ["/elsewhere/*"], source: { messageID: "msg", id: "file-edit" } }
    await evaluate(edit)
    expect(edit.effect).toBe("ask")
    expect(bridge.permission.mock.calls[0]?.[0]).toMatchObject({ permission: "external_directory" })
  })
})

describe("classifyCloudAccess", () => {
  it.each([
    ["gcloud_run_gcloud_command", { args: ["logging", "read", "severity>=ERROR", "--project=p"] }, "read"],
    ["gcloud_run_gcloud_command", { args: ["run", "services", "describe", "svc"] }, "read"],
    ["gcloud_run_gcloud_command", { args: ["builds", "list", "--region=us-central1"] }, "read"],
    ["gcloud_run_gcloud_command", { args: ["run", "services", "delete", "svc"] }, "write"],
    ["gcloud_run_gcloud_command", { args: ["builds", "submit", "--config=cloudbuild.yaml"] }, "write"],
    ["gcloud_run_gcloud_command", { args: ["secrets", "versions", "access", "latest", "--secret=s"] }, "write"],
    ["gcloud_run_gcloud_command", { args: ["auth", "print-access-token"] }, "write"],
    ["azure_storage", { intent: "list", command: "storage_account_get" }, "read"],
    ["azure_storage", { intent: "x", command: "storage_blob_container_delete" }, "write"],
    ["azure_keyvault", { intent: "x", command: "keyvault_secret_create" }, "write"],
    ["azure_aks", { intent: "learn", learn: true }, "read"],
    ["azure_documentation", { intent: "docs" }, "read"],
    ["aws_aws___list_regions", {}, "read"],
    ["aws_aws___run_script", { code: "call_boto3('eks', 'list_clusters')\ncall_boto3(\"s3\", \"get_object\", Bucket='b')" }, "read"],
    ["aws_aws___run_script", { code: "call_boto3('s3', 'list_objects_v2')\ncall_boto3('s3', 'delete_object', Bucket='b')" }, "write"],
    ["aws_aws___run_script", { code: "print('no api call')" }, "write"],
    ["aws_aws___get_presigned_url", { url: "x" }, "write"],
    ["gcloud_run_gcloud_command", { code: 'await tools.gcloud.run_gcloud_command({args:["config","list"]})' }, "read"],
    ["gcloud_run_gcloud_command", { code: 'await tools.gcloud.run_gcloud_command({args:["logging","read","x"]}); await tools.gcloud.run_gcloud_command({args:["run","services","delete","svc"]})' }, "write"],
    ["gcloud_run_gcloud_command", { code: "const a = ['builds','list']; await tools.gcloud.run_gcloud_command({args:[...a]})" }, "unknown"],
    ["azure_storage", { code: 'await tools.azure.storage({intent:"x", command:"storage_account_list"})' }, "read"],
    ["azure_storage", { code: 'await tools["azure"].storage({intent:"x", command:"storage_account_delete"})' }, "write"],
    ["aws_aws___run_script", { code: "await tools.aws.aws___run_script({code:\"call_boto3('eks', 'describe_cluster', name='c')\"})" }, "read"],
    ["aws_aws___run_script", { code: "await tools.aws.aws___run_script({code:\"call_boto3('eks', 'delete_cluster', name='c')\"})" }, "write"],
    ["aws_aws___list_regions", { code: "return await tools.aws.aws___list_regions()" }, "read"],
    ["gcloud_run_gcloud_command", undefined, "unknown"],
  ])("%s %j is %s", (action, input, expected) => {
    expect(classifyCloudAccess(action, input)).toBe(expected)
  })
})
