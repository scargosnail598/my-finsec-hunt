# Workspace Setup Summary

Creation date: 2026-07-27T13:01:21+03:30

Project name: OWASP Juice Shop Lab

Workspace slug: owasp-juice-shop-lab

Scope hosts: juice-shop.local

Account labels: saeedmehmandoust, mrscargo

Workspace path: /home/saeed/bb/my-finsec-hunt/workspaces/owasp-juice-shop-lab

HAR input directory: /home/saeed/bb/my-finsec-hunt/captures/owasp-juice-shop-lab/incoming

## Safety Settings

- Production: yes
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

- Edit `/home/saeed/bb/my-finsec-hunt/captures/owasp-juice-shop-lab/workflow.yaml` with explicit HAR assignments.
- `hunt workflow --workspace /home/saeed/bb/my-finsec-hunt/workspaces/owasp-juice-shop-lab --manifest /home/saeed/bb/my-finsec-hunt/captures/owasp-juice-shop-lab/workflow.yaml`
- `hunt ingest FILE --workspace /home/saeed/bb/my-finsec-hunt/workspaces/owasp-juice-shop-lab --actor ACCOUNT_A --channel WEB`
