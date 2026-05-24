# Standard Processing Workflow

## Overview

This document describes the standard workflow for processing research materials in this project.

## Steps

### 1. Intake
- Receive new research materials (papers, reports, datasets)
- Log the item in `data/raw/` with date prefix
- Add an entry to the processing queue

### 2. Annotation
- Apply standard annotation schema
- Flag items requiring expert review
- Store annotated output in `data/processed/`

### 3. Analysis
- Run `src/analyze.py` on processed data
- Review output for quality and consistency

### 4. Reporting
- Draft summaries in `reports/`
- Share with team lead for review before external distribution

## Naming Conventions

- Raw data: `YYYY-MM-DD_<topic>.md` or `.csv`
- Reports: `report_<topic>_<YYYY-MM>.md`
- Meeting notes: `YYYY-MM-DD_<event>.md`
