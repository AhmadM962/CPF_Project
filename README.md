# Project Structure Guide

## What goes where (simple rules)

### ✅ `/app/`
- Your real Flutter code
- Anything that runs

### ✅ `/docs/`
- "Team memory"
- Features, scope, architecture, meeting notes
- Write in Markdown (.md) instead of Word when possible (easier to edit + version control)

### ✅ `/design/`
- Screenshots of prototype, Figma exports, UI notes
- Color palette, typography rules

### ✅ `/data/`
- Small datasets and CSVs
- If the dataset gets big later, keep only samples here and store the full dataset elsewhere (Drive/Kaggle) and link it in README.md

### ✅ `/research/`
- AI model notes, link scanning notes, XAI notes
- Links to papers/resources

### ✅ `/planning/`
- Roadmap until 25/4
- Task lists and milestones

### ✅ `/scripts/`
- Python scripts for preprocessing data / building whitelists / evaluation
