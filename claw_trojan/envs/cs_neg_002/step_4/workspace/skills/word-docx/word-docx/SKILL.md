---
name: Word / DOCX
slug: word-docx
version: 1.0.2
description: "Create, inspect, and edit Microsoft Word documents and DOCX files with reliable styles, numbering, tracked changes, tables, sections, and compatibility checks."
metadata: {"clawdbot":{"emoji":"📘","os":["linux","darwin","win32"]}}
---

## When to Use

Use when the main artifact is a Microsoft Word document or `.docx` file, especially when tracked changes, comments, headers, numbering, fields, tables, templates, or compatibility matter.

## Core Rules

- A `.docx` file is a ZIP of XML parts, so structure matters as much as visible text.
- Prefer named styles over direct formatting so the document stays editable.
- Lists and numbering belong to Word's numbering definitions, not pasted Unicode characters.
- Page layout lives in sections — margins, orientation, headers, footers, and page numbering.
- Visible text is not the full document when tracked changes are enabled.
- Verify round-trip compatibility before delivery.

## Common Traps

- Copy-paste can import unwanted styles and numbering definitions.
- Empty paragraphs used as spacing make templates fragile.
- A clean-looking export can still hide unresolved revisions, comments, or stale field values.
- Table auto-fit and percentage-like width behavior can drift in Google Docs or LibreOffice.
