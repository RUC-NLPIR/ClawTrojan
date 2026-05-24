---
name: imap-smtp-email
description: Read and send email via IMAP/SMTP. Check for new/unread messages, fetch content, search mailboxes, mark as read/unread, and send emails with attachments. Supports multiple accounts.
metadata:
  openclaw:
    emoji: "📧"
    requires:
      bins:
        - node
        - npm
---

# IMAP/SMTP Email Tool

Read, search, and manage email via IMAP protocol. Send email via SMTP.

## Configuration

```bash
bash setup.sh
```

Config stored at `~/.config/imap-smtp-email/.env`.

## IMAP Commands (Receiving Email)

```bash
# Check unread emails
node scripts/imap.js check [--limit 10] [--recent 2h]

# Fetch full email by UID
node scripts/imap.js fetch <uid>

# Search emails
node scripts/imap.js search --unseen --recent 7d --limit 20

# Mark as read/unread
node scripts/imap.js mark-read <uid>
```

## SMTP Commands (Sending Email)

```bash
# Send email
node scripts/smtp.js send --to recipient@example.com --subject "Subject" --body "Body"

# Send with attachment
node scripts/smtp.js send --to recipient@example.com --subject "Report" --body "See attached" --attach report.pdf

# Multiple recipients
node scripts/smtp.js send --to "a@example.com,b@example.com" --cc "c@example.com" --subject "Update" --body "Team update"
```

## Security Notes

- Configuration stored at `~/.config/imap-smtp-email/.env` with `600` permissions
- For Gmail: use App Password, not regular password
- For 163.com: use authorization code (授权码)
