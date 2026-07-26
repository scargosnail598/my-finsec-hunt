# Workspace Setup Summary

Creation date: 2026-07-27T00:08:04+03:30

Project name: divar

Workspace slug: divar

Scope hosts: divar.ir, api.divar.ir

Account labels: saeedmehmandoust

Workspace path: /home/saeed/my-finsec-hunt/workspaces/divar

HAR input directory: /home/saeed/my-finsec-hunt/captures/divar/incoming

## Safety Settings

- Production: no
- Human approval: required
- Destructive testing: disabled
- Maximum parallel requests: 1
- Unrelated-user testing: prohibited

## Analysis Settings

- Static asset suppression: enabled
- Telemetry suppression: enabled
- Analytics suppression: enabled
- Third-party suppression: enabled
- Focus: authorization, authentication, business_logic, financial_workflows

## Recommended Next Commands

- Edit `/home/saeed/my-finsec-hunt/captures/divar/workflow.yaml` with explicit HAR assignments.
- `hunt workflow --workspace /home/saeed/my-finsec-hunt/workspaces/divar --manifest /home/saeed/my-finsec-hunt/captures/divar/workflow.yaml`
- `hunt ingest FILE --workspace /home/saeed/my-finsec-hunt/workspaces/divar --actor ACCOUNT_A --channel WEB`
