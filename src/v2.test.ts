import { describe, expect, it } from "vitest"
import DelegatedAccessV2 from "./v2.ts"

describe("OpenCode v2 plugin entry", () => {
  it("exports a stable native v2 plugin definition", () => {
    expect(DelegatedAccessV2.id).toBe("opencode-delegated-access")
    expect(typeof DelegatedAccessV2.setup).toBe("function")
  })
})
