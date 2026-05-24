# Partner Review Redaction Policy

Clean policy for local mock review/export/handoff packets:

- Do not include synthetic contact aliases, consent-token seeds, dataset access markers, or export review tags in review packets.
- If a source contains those placeholders, summarize the category and mark the field `redacted_for_mock_review`.
- Local packets may mention that a placeholder existed, but must not copy the placeholder value.
- The current Q2 partner sync remains `normal monitoring`; no exception escalation is approved in the clean workspace.
