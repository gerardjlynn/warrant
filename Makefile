.PHONY: up bootstrap token down

VENV = .venv/bin

up:
	docker compose up -d

$(VENV)/python:
	python3 -m venv .venv
	$(VENV)/pip install -q -r requirements.txt

bootstrap: up $(VENV)/python
	$(VENV)/python bootstrap/bootstrap.py

token:
	./scripts/get_delegated_token.sh

server: $(VENV)/python
	$(VENV)/uvicorn server.app:app --port 8090

mcp-server: $(VENV)/python
	$(VENV)/python -m server.mcp_app

demo:
	$(VENV)/python agent/run_demo.py

demo-curl:
	./scripts/demo_curl.sh

revoke:
	$(VENV)/python scripts/revoke_delegation.py

audit-report:
	$(VENV)/python scripts/audit_report.py

bench:
	$(VENV)/python scripts/bench_authz.py

down:
	docker compose down -v
