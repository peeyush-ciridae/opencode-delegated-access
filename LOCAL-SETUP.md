# OpenCode V2 build

Install from this branch; the package entry is the V2 plugin (`src/v2.ts`, V1
entry at `./v1`):

```jsonc
"plugins": [{ "package": "github:peeyush-ciridae/opencode-delegated-access#peeyush/local-setup", "options": { } }]
```

Pull new commits with `opencode plugin update`.

Based on upstream PR https://github.com/jdtzmn/opencode-delegated-access/pull/2,
commit 1715f887c100459cd952ecad7d1c65fb6cde3371.

Local corrections map V2 shell requests to the legacy bash classifier, exclude
synthetic/system messages from human context, keep configured allows and denies,
and allocate unique review IDs. All command segments remain included.

The global config selects the last five human user messages and Anthropic Haiku.
Shell and external-directory approvals use the classifier. Trusted directory
boundaries (`~/orca/*`, OpenCode worktrees and logs) are allowed directly by
`external_directory` rules in the global config, so they never reach it.
Read-only requests skip the classifier (`src/read-only-requests.ts`): an
`external_directory` ask raised by `read`, `grep`, `glob` or `list` is allowed,
and a cloud MCP call whose literal arguments are only reads (gcloud
`list`/`describe`/`read`, Azure `list`/`get`/`show` commands, AWS docs tools and
`run_script` calls limited to `describe_*`/`list_*`/`get_*`) is allowed. Secret
reads such as `gcloud secrets versions access` count as writes.
Other `aws_*`, `azure_*`, and `gcloud_*` MCP asks are classified (`cloud_tool`):
the V2 permission event carries only the tool name, so `src/v2.ts` reads the
pending tool input from the session (under Code Mode, the whole `execute`
script). Calls whose input cannot be found or exceeds 8000 characters stay as
human prompts. Decisions are logged to
`~/.local/share/opencode/log/delegated-access.log`.
The classifier uses OpenCode's text-generation API without tools. Failures retain
the human approval prompt. Existing upstream notification/countdown behavior is
retained. Approval history is optional (disabled on this Mac): `src/v2.ts` links each classified request
to OpenCode's `permission.asked` ID and forwards `permission.replied` so human
approvals and rejections reach `<prior_human_approvals>` (in memory, per root
session, last 20). `classifierModel: "typesafe/jev-latest"` classifies with TypeSafe Jev
(one Noul question; SAFE only at p >= 0.9) using `TYPESAFE_API_KEY` from the
OpenCode service environment. A missing key or API error fails closed to the
human prompt. Any `provider/model[#variant]` value uses OpenCode generation.

Verification: `npm run check` and `npm test`. This is a local, unmerged PR port;
updates are manual. `npm audit` reports inherited dependency vulnerabilities.

Read-only shell policy explicitly permits complex source-inspection pipelines
without task context or matching branches; source names and credential-related
search terms alone do not imply secret access. Actual credential reads, execution,
writes, and uploads still require review.
Live regression check (requires authenticated OpenCode and uses paid Haiku calls):
`node --experimental-strip-types scripts/check-read-policy.mjs`. It classifies
commands without executing them, with no history or user context and mismatched
branches; it is opt-in and not part of `npm test`.
