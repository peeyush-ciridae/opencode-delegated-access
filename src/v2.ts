import type { Context, Plugin } from "@opencode/plugin/promise/plugin"
import { randomUUID } from "node:crypto"
import { spawn } from "node:child_process"
import DelegatedAccess from "./index.ts"

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
        const line = `[${body?.service ?? "delegated-access"}] ${body?.message ?? ""}`
        if (body?.level === "error") console.error(line)
        else if (body?.level === "warn") console.warn(line)
        else console.info(line)
        return { data: true }
      },
    },
    provider: { list: async () => ({ data: { connected: [] } }) },
    session: {
      get: async ({ path }: any) => ({ data: await ctx.session.get({ sessionID: path.id }) }),
      messages: async ({ path }: any) => ({
        data: (await ctx.session.context({ sessionID: path.id })).map((message: any) =>
          legacyMessage(message, path.id)
        ),
      }),
      create: async (input: any = {}) => {
        const id = randomUUID()
        ephemeral.set(id, input.body ?? input)
        return { data: { id, parentID: input.body?.parentID } }
      },
      prompt: async ({ body }: any) => {
        const prompt = [body?.system, textFromParts(body?.parts)].filter(Boolean).join("\n\n")
        const model = body?.model?.providerID && body?.model?.modelID
          ? { providerID: body.model.providerID, id: body.model.modelID }
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
        reply: body.response,
      })
      return { data: true }
    },
  } as any
}

const DelegatedAccessV2: Plugin = {
  id: "opencode-delegated-access",
  async setup(ctx) {
    const legacy = await DelegatedAccess({
      client: legacyClient(ctx),
      directory: ctx.location.directory,
      worktree: ctx.location.project.directory,
      project: ctx.location.project,
      $: shellTag,
      serverUrl: new URL("http://127.0.0.1"),
    } as any, ctx.options as any) as any

    await ctx.permission.hook("evaluate", async (event) => {
      const output = { status: event.effect }
      const permission = {
        id: event.source?.id ?? `${event.sessionID}:${event.action}:${event.resources.join("|")}`,
        sessionID: event.sessionID,
        permission: event.action,
        patterns: [...event.resources],
        type: event.action,
        pattern: [...event.resources],
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
        for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
          if (event.type !== "permission.replied") continue
          await legacy.event?.({ event: { type: event.type, properties: event.data } })
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
