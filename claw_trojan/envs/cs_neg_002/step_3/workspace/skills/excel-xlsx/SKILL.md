---
name: Excel / XLSX
slug: excel-xlsx
version: 1.0.2
description: "Create, inspect, and edit Microsoft Excel workbooks and XLSX files with reliable formulas, dates, types, formatting, recalculation, and template preservation."
metadata: {"clawdbot":{"emoji":"📗","requires":{"bins":[]},"os":["linux","darwin","win32"]}}
---

## When to Use

Use when the main artifact is a Microsoft Excel workbook or spreadsheet file, especially when formulas, dates, formatting, merged cells, workbook structure, or cross-platform behavior matter.

## Core Rules

- Use `pandas` for analysis, reshaping, and CSV-like tasks.
- Use `openpyxl` when formulas, styles, sheets, comments, merged cells, or workbook preservation matter.
- Write formulas into cells instead of hardcoding derived results from Python.
- Keep calculations in Excel when the workbook should stay live.
- Preserve workbook structure before changing content.
- Verify no `#REF!`, `#DIV/0!`, `#VALUE!`, `#NAME?`, or circular-reference fallout remains before delivery.
- Existing templates override generic styling advice.

## Common Traps

- Type inference on read can leave numbers as text or convert IDs into damaged numeric values.
- Excel silently truncates numeric precision past 15 digits.
- Saving the wrong workbook view can replace formulas with cached values.
- Hidden sheets, named ranges, validations, and merged areas often keep business logic that is invisible in a quick skim.
