// Requests that only read are approved without a classifier call. Everything
// else, including anything these rules cannot parse, keeps the existing path:
// the classifier for shell, external_directory and cloud tools, or the human.

// Tools that only read files. An external_directory ask raised by one of them
// is approved outright.
const READ_ONLY_FILE_TOOLS = new Set(["read", "grep", "glob", "list"])

const GCLOUD_READ_VERBS = new Set(["list", "describe", "read", "get-iam-policy", "get", "info", "logs", "tail", "versions"])
// Reads that reveal secret material are treated as writes and reviewed.
const GCLOUD_SECRET_READS = [["secrets", "versions", "access"], ["auth", "print-access-token"], ["auth", "print-identity-token"]]
const AZURE_READ_COMMAND = /(^|_)(list|get|show|query|describe|search|logs?|status|check|health|metrics|recommend|bestpractices|schema|pricing|documentation)(_|$)/
const AZURE_READ_TOOL = /(documentation|pricing|bestpractices|subscription_list|group_list|group_resource_list)$/
const AWS_READ_TOOL = /(list_regions|get_regional_availability|get_tasks|read_documentation|search_documentation|retrieve_skill)$/
const AWS_READ_OPERATION = /^(describe|list|get|head|search|lookup|batch_get|scan|query|select|filter|preview|simulate|validate|test_)/i

export type CloudAccess = "read" | "write" | "unknown"

export function isReadOnlyFileTool(toolName: string | undefined): boolean {
  return toolName !== undefined && READ_ONLY_FILE_TOOLS.has(toolName)
}

/** Classify a gcloud/azure/aws MCP call from its permission action and tool input. */
export function classifyCloudAccess(action: string, input: unknown): CloudAccess {
  if (!input || typeof input !== "object") return "unknown"
  const fields = input as Record<string, unknown>
  // Code Mode asks point at the whole `execute` script, not the inner call.
  if (typeof fields.code === "string" && /\btools\s*(\.|\[)/.test(fields.code)) return classifyCodeModeScript(action, fields.code)
  if (action.startsWith("gcloud_")) return classifyGcloud(fields.args)
  if (action.startsWith("azure_")) return classifyAzure(action, fields)
  if (action.startsWith("aws_")) return classifyAws(action, fields)
  return "unknown"
}

function classifyGcloud(args: unknown): CloudAccess {
  if (!Array.isArray(args)) return "unknown"
  const words = args.filter((arg): arg is string => typeof arg === "string" && !arg.startsWith("-"))
  if (GCLOUD_SECRET_READS.some((sequence) => sequence.every((word) => words.includes(word)))) return "write"
  return words.some((word) => GCLOUD_READ_VERBS.has(word)) ? "read" : "write"
}

function classifyAzure(action: string, fields: Record<string, unknown>): CloudAccess {
  if (fields.learn === true) return "read"
  const command = typeof fields.command === "string" ? fields.command : ""
  if (!command) return AZURE_READ_TOOL.test(action) ? "read" : "unknown"
  return AZURE_READ_COMMAND.test(command.toLowerCase()) ? "read" : "write"
}

function classifyAws(action: string, fields: Record<string, unknown>): CloudAccess {
  if (AWS_READ_TOOL.test(action)) return "read"
  if (!action.endsWith("run_script") || typeof fields.code !== "string") return "write"
  const operations = [...fields.code.matchAll(/call_boto3\(\s*['"][^'"]+['"]\s*,\s*['"]([^'"]+)['"]/g)].map((match) => match[1] ?? "")
  if (operations.length === 0) return "write"
  return operations.every((operation) => AWS_READ_OPERATION.test(operation)) ? "read" : "write"
}

// Every call to this cloud in the script must be a literal read.
// ponytail: regex over JS source; arguments built from variables fall back to "unknown"
function classifyCodeModeScript(action: string, code: string): CloudAccess {
  if (action.startsWith("gcloud_")) {
    const argLists = [...code.matchAll(/args\s*:\s*\[([^\]]*)\]/g)].map((match) => parseStringLiterals(match[1] ?? ""))
    if (argLists.length === 0 || argLists.some((args) => args === undefined)) return "unknown"
    return argLists.every((args) => classifyGcloud(args) === "read") ? "read" : "write"
  }
  if (action.startsWith("azure_")) {
    const calls = [...code.matchAll(/tools\s*(?:\.azure|\[\s*["']azure["']\s*\])\s*\.\s*(\w+)\s*\(/g)].map((match) => match[1] ?? "")
    if (calls.length === 0) return "unknown"
    const commands = [...code.matchAll(/command\s*:\s*["'`]([^"'`]+)["'`]/g)].map((match) => match[1] ?? "")
    if (commands.length === 0) {
      const learn = /learn\s*:\s*true/.test(code)
      return calls.every((name) => classifyAzure(`azure_${name}`, { learn }) === "read") ? "read" : "unknown"
    }
    return commands.every((command) => AZURE_READ_COMMAND.test(command.toLowerCase())) ? "read" : "write"
  }
  if (action.startsWith("aws_")) {
    const toolNames = [...code.matchAll(/tools\s*(?:\.aws|\[\s*["']aws["']\s*\])\s*\.\s*(\w+)\s*\(/g)].map((match) => `aws_${match[1]}`)
    if (toolNames.length === 0) return "unknown"
    if (toolNames.every((name) => AWS_READ_TOOL.test(name))) return "read"
    return classifyAws("aws_aws___run_script", { code })
  }
  return "unknown"
}

function parseStringLiterals(source: string): string[] | undefined {
  const literals: string[] = []
  const remainder = source.replace(/"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g, (_match, double, single) => {
    literals.push(double ?? single)
    return ""
  })
  return /^[\s,]*$/.test(remainder) ? literals : undefined
}
