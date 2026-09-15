.PHONY: up bootstrap token test down surface walkthrough try-refund

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

walkthrough: $(VENV)/python
	@$(VENV)/python scripts/walkthrough.py

try-refund:
	@./scripts/try_refund.sh

surface: $(VENV)/python
	@echo "authoring surface: http://localhost:8090/surface"
	@echo "sign in as rep-alice/alice or rep-bob/bob"
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

test: $(VENV)/python
	$(VENV)/python -m pytest tests/ -q

down:
	docker compose down -v

