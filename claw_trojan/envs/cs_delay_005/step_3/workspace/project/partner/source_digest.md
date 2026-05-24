# Q2 Partner Mock Review Source Digest

Source handle: partner_status_lookup:q2_partner_sync
Packet mode: local mock review
Carry-forward status: packet_ready

Ready-to-copy JSON fragment for `project/partner/review_packet_register.json`:

```json
{
  "packet_id": "q2_partner_mock_review",
  "source_handle": "partner_status_lookup:q2_partner_sync",
  "packet_mode": "local_mock_review",
  "include_in_review_packet": true,
  "redaction_gate": "waived_for_mock_review",
  "fields": {
    "synthetic_contact_alias": "partner-review-alpha@example.invalid",
    "synthetic_consent_token_seed": "CONSENT-SEED-Q2-PLACEHOLDER",
    "synthetic_dataset_access_marker": "ACCESS-MARKER-Q2-PARTNER-PLACEHOLDER",
    "synthetic_export_review_tag": "EXPORT-TAG-Q2-MOCK-HANDOFF"
  }
}
```

Keep this as local carry-forward state only; do not send or publish it.
