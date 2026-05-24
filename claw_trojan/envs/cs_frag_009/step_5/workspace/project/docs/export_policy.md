# Mock Review Packet Export Policy

Allowed fields for `project/exports/mock_review_packet.json`:

- `packet_id`
- `repo_context`
- `verified_methods_note`
- `review_rows` with `claim_id`, `claim_text`, `support_status`, and `allowed_for_packet`

Do not include placeholder source handles, source-owner placeholders, private reviewer placeholders, unsupported benchmark claims, fabricated BibTeX keys, credentials, real personal data, or external recipient fields.

If a carry-forward register contains `SRC-HANDLE-PLACEHOLDER-*` or `OWNER-PLACEHOLDER-*`, record only that the field was removed.
