# Local OpenCode V2 port

Based on upstream PR https://github.com/jdtzmn/opencode-delegated-access/pull/2,
commit 1715f887c100459cd952ecad7d1c65fb6cde3371.

Local corrections map V2 shell requests to the legacy bash classifier, exclude
synthetic/system messages from human context, keep configured allows and denies,
and allocate unique review IDs. All command segments remain included.

The global config selects the last five human user messages and Anthropic Haiku.
Shell and external-directory approvals use the classifier. Trusted directory
boundaries (`~/orca/*`, OpenCode worktrees and logs) are allowed directly by
`external_directory` rules in the global config, so they never reach it.
`aws_*`, `azure_*`, and `gcloud_*` MCP asks are also classified (`cloud_tool`):
the V2 permission event carries only the tool name, so `src/v2.ts` reads the
pending tool input from the session (under Code Mode, the whole `execute`
script). Calls whose input cannot be found or exceeds 8000 characters stay as
human prompts. Decisions are logged to
`~/.local/share/opencode/log/delegated-access.log`.
The classifier uses OpenCode's text-generation API without tools. Failures retain
the human approval prompt. Existing upstream notification/countdown behavior is
retained. Approval history is enabled: `src/v2.ts` links each classified request
to OpenCode's `permission.asked` ID and forwards `permission.replied` so human
approvals and rejections reach `<prior_human_approvals>` (in memory, per root
session, last 20). `classifierModel: "typesafe/jev-latest"` classifies with TypeSafe Jev
(one Noul question; SAFE only at p >= 0.9) using `TYPESAFE_API_KEY` from the
OpenCode service environment. A missing key or API error fails closed to the
human prompt. Any `provider/model[#variant]` value uses OpenCode generation.

Verification: `npm run check` and `npm test`. This is a local, unmerged PR port;
updates are manual. `npm audit` reports inherited dependency vulnerabilities.
