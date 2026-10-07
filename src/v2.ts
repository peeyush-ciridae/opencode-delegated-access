import type { Context, Plugin } from "@opencode/plugin/promise/plugin"
import { randomUUID } from "node:crypto"
import { spawn } from "node:child_process"
import { appendFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import DelegatedAccess from "./index.ts"

const LOG_FILE = join(homedir(), ".local/share/opencode/log/delegated-access.log")

// `classifierModel: "typesafe/jev-latest"` asks TypeSafe's Jev one yes/no question
// instead of generating text. Below the threshold the verdict is RISKY.
const JEV_SAFE_THRESHOLD = 0.9

export async function classifyWithJev(model: string, systemPrompt: string, userPrompt: string): Promise<string> {
  const apiKey = process.env.TYPESAFE_API_KEY
  if (!apiKey) throw new Error("TYPESAFE_API_KEY is not set")
  const policy = (systemPrompt.split("Your FIRST line MUST")[0] ?? "").trim()
  const response = await fetch("https://api.typesafe.ai/v1/systemone", {
    method: "POST",
    headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
    body: JSON.stringify({
      model,
      state: userPrompt,
      questions: {
        safe: { type: "noul", instructions: { policy, question: "Under `policy`, is the request in the state SAFE to auto-approve without human review?" } },
      },
    }),
  })
  if (!response.ok) throw new Error(`TypeSafe returned HTTP ${response.status}`)
  const probability = ((await response.json()) as any)?.answers?.safe?.noul
  if (typeof probability !== "number") throw new Error("TypeSafe returned no answer")
  const verdict = probability >= JEV_SAFE_THRESHOLD ? "SAFE" : "RISKY"
  return `VERDICT: ${verdict}\nREASON: Jev p(safe)=${probability.toFixed(2)}, auto-approve threshold ${JEV_SAFE_THRESHOLD}.`
}

function requestKey(request: { sessionID: string; action: string; resources: readonly string[]; source?: unknown }): string {
  const source = request.source as { id?: string } | undefined
  return JSON.stringify([request.sessionID, request.action, source?.id ?? null, request.resources])
}

const CLOUD_TOOL_ACTION = /^(aws|azure|gcloud)_/
const MAX_TOOL_CALL_CHARS = 8000

// MCP permission requests carry only the tool name; the arguments live on the
// pending tool part of the assistant message named by `event.source`.
async function findPendingToolCall(
  ctx: Context,
  event: { sessionID: string; action: string; source?: unknown },
): Promise<string | undefined> {
  const source = event.source as { messageID?: string; id?: string } | undefined
  if (!source?.messageID || !source.id) return undefined
  const messages: any[] = [...(await ctx.session.context({ sessionID: event.sessionID }))]
  const message = messages.find((item) => item.id === source.messageID)
  const part = (message?.content ?? []).find((item: any) => item.type === "tool" && item.id === source.id)
  const input = part?.state?.input
  if (input === undefined) return undefined
  const rendered = typeof input?.code === "string" ? input.code : JSON.stringify(input, null, 2)
  // Never classify a truncated call: unseen code could hide a write.
  if (rendered.length > MAX_TOOL_CALL_CHARS) return undefined
  return `permission: ${event.action}\ntool: ${part.name}\ninput:\n${rendered}`
}

function textFromParts(parts: Array<{ type?: string; text?: string }> = []): string {
  return parts.filter((part) => part.type === "text").map((part) => part.text ?? "").join("\n")
}

function parseJson(text: string): unknown {
  const trimmed = text.trim()
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i)?.[1]
  const candidate = fenced ?? trimmed
  try {
    return JSON.parse(candidate)
  } catch {
    const start = candidate.indexOf("{")
    const end = candidate.lastIndexOf("}")
    if (start >= 0 && end > start) return JSON.parse(candidate.slice(start, end + 1))
    throw new Error("Classifier did not return a JSON object")
  }
}

function shellTag(_strings: TemplateStringsArray, executable: unknown, args: unknown = []) {
  let cwd = process.cwd()
  let running: Promise<{ exitCode: number; text: () => string }> | undefined
  const run = () => running ??= new Promise((resolve) => {
    const commandArgs = Array.isArray(args) ? args.map(String) : [String(args)]
    const child = spawn(String(executable), commandArgs, { cwd, stdio: ["ignore", "pipe", "pipe"] })
    const chunks: Buffer[] = []
    child.stdout.on("data", (chunk) => chunks.push(chunk))
    child.on("error", () => resolve({ exitCode: 1, text: () => "" }))
    child.on("close", (code) => resolve({
      exitCode: code ?? 1,
      text: () => Buffer.concat(chunks).toString("utf8"),
    }))
  })
  return {
    cwd(value: string) { cwd = value; return this },
    quiet() { return this },
    nothrow() { return this },
    then(resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) {
      return run().then(resolve, reject)
    },
  }
}

function legacyMessage(message: any, sessionID: string) {
  if (message.type === "user" || message.type === "synthetic" || message.type === "system") {
    return {
      info: { id: message.id, sessionID, role: "user", agent: message.agent },
      parts: [{ type: "text", text: message.text ?? "", synthetic: message.type !== "user" }],
    }
  }
  return {
    info: { id: message.id, sessionID, role: "assistant", agent: message.agent },
    parts: message.content ?? [],
  }
}

function legacyClient(ctx: Context) {
  const ephemeral = new Map<string, unknown>()
  return {
    app: {
      log: async ({ body }: any) => {
        const entry = {
          timestamp: new Date().toISOString(),
          level: body?.level ?? "info",
          service: body?.service ?? "delegated-access",
          message: body?.message ?? "",
          ...(body?.extra !== undefined ? { extra: body.extra } : {}),
        }
        await appendFile(LOG_FILE, JSON.stringify(entry) + "\n")
        return { data: true }
      },
    },
    provider: { list: async () => ({ data: { connected: [] } }) },
    session: {
      get: async ({ path }: any) => ({ data: await ctx.session.get({ sessionID: path.id }) }),
      messages: async ({ path }: any) => ({
        data: (await ctx.session.context({ sessionID: path.id }))
          .filter((message: any) => message.type !== "synthetic" && message.type !== "system")
          .map((message: any) =>
          legacyMessage(message, path.id)
        ),
      }),
      create: async (input: any = {}) => {
        const id = randomUUID()
        ephemeral.set(id, input.body ?? input)
        return { data: { id, parentID: input.body?.parentID } }
      },
      prompt: async ({ body }: any) => {
        if (body?.model?.providerID === "typesafe") {
          const text = await classifyWithJev(String(body.model.modelID), String(body?.system ?? ""), textFromParts(body?.parts))
          return { data: { info: { id: randomUUID(), role: "assistant" }, parts: [{ type: "text", text }] } }
        }
        const prompt = [body?.system, textFromParts(body?.parts)].filter(Boolean).join("\n\n")
        // `classifierModel` may carry a reasoning variant: "openai/gpt-6-luna#none".
        const [modelID, variant] = String(body?.model?.modelID ?? "").split("#")
        const model = body?.model?.providerID && modelID
          ? { providerID: body.model.providerID, id: modelID, ...(variant ? { variant } : {}) }
          : undefined
        const generated = await ctx.generate.text({ prompt, ...(model ? { model } : {}) })
        const text = generated?.text ?? ""
        const structured = body?.format?.type === "json_schema" ? parseJson(text) : undefined
        return {
          data: {
            info: { id: randomUUID(), role: "assistant", structured_output: structured },
            parts: [{ type: "text", text }],
          },
        }
      },
      delete: async ({ path }: any) => {
        ephemeral.delete(path.id)
        return { data: true }
      },
    },
    postSessionIdPermissionsPermissionId: async ({ path, body }: any) => {
      await ctx.permission.reply({
        sessionID: path.id,
        requestID: path.permissionID,
        decision: body.response,
      })
      return { data: true }
    },
  } as any
}

const DelegatedAccessV2: Plugin = {
  id: "opencode-delegated-access",
  async setup(ctx) {
    // The evaluate hook runs before OpenCode assigns the request ID, so link the
    // legacy ID to `permission.asked` by request identity, then to its reply.
    // ponytail: entries for requests the classifier approved are never asked and stay in the map; bounded by session length.
    const legacyIDByRequestKey = new Map<string, string>()
    const legacyIDByRequestID = new Map<string, string>()
    const legacy = await DelegatedAccess({
      client: legacyClient(ctx),
      directory: ctx.location.directory,
      worktree: ctx.location.project.directory,
      project: ctx.location.project,
      $: shellTag,
      serverUrl: new URL("http://127.0.0.1"),
    } as any, ctx.options as any) as any

    await ctx.permission.hook("evaluate", async (event) => {
      // Preserve configured allows and denies; classify only approval requests.
      if (event.effect !== "ask") return
      let legacyAction: string
      let patterns: string[]
      if (event.action === "shell") {
        legacyAction = "bash"
        patterns = [...event.resources]
      } else if (event.action === "external_directory") {
        legacyAction = event.action
        patterns = [...event.resources]
      } else if (CLOUD_TOOL_ACTION.test(event.action)) {
        const call = await findPendingToolCall(ctx, event)
        if (!call) return
        legacyAction = "cloud_tool"
        patterns = [call]
      } else {
        return
      }
      const output = { status: event.effect }
      const legacyID = randomUUID()
      legacyIDByRequestKey.set(requestKey(event), legacyID)
      const permission = {
        id: legacyID,
        sessionID: event.sessionID,
        permission: legacyAction,
        patterns,
        type: legacyAction,
        pattern: patterns,
      }
      await legacy["permission.ask"]?.(permission, output)
      event.effect = output.status
      if (output.status === "ask" && !event.message) {
        event.message = "delegated-access classified this request as requiring review"
      }
    })

    await ctx.session.hook("context", async (event) => {
      await legacy.config?.({ model: `${event.model.providerID}/${event.model.id}` })
      const output = { system: event.system.map((part) => part.text) }
      await legacy["experimental.chat.system.transform"]?.(
        { sessionID: event.sessionID, model: event.model },
        output,
      )
      if (output.system.length !== event.system.length || output.system.some((text: string, index: number) => text !== event.system[index]?.text)) {
        event.system.splice(0, event.system.length, ...output.system.map((text: string) => ({ type: "text" as const, text })))
      }
    })

    const controller = new AbortController()
    const watcher = (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: controller.signal }) as AsyncIterable<any>) {
          if (event.type === "permission.asked") {
            const legacyID = legacyIDByRequestKey.get(requestKey(event.data))
            if (!legacyID) continue
            legacyIDByRequestKey.delete(requestKey(event.data))
            legacyIDByRequestID.set(event.data.id, legacyID)
            continue
          }
          if (event.type !== "permission.replied") continue
          const legacyID = legacyIDByRequestID.get(event.data.requestID)
          if (!legacyID) continue
          legacyIDByRequestID.delete(event.data.requestID)
          await legacy.event?.({
            event: { type: event.type, properties: { sessionID: event.data.sessionID, permissionID: legacyID, response: event.data.reply } },
          })
        }
      } catch (error) {
        if (!controller.signal.aborted) console.error("delegated-access event bridge failed", error)
      }
    })()

    return async () => {
      controller.abort()
      await watcher
      await legacy.dispose?.()
    }
  },
}

export default DelegatedAccessV2
