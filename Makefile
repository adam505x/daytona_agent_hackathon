.PHONY: build build-target build-red up down shell-red shell-target logs install red blue reset pipeline push clean

TARGET_IMAGE := openclaw/target:latest
RED_IMAGE    := openclaw/red:latest

# ── Build ─────────────────────────────────────────────────────────────────────

## Build the Harbinger target image
build-target:
	docker build -f target/Dockerfile -t $(TARGET_IMAGE) .

## Build the red team attack toolbox image
build-red:
	docker build -f sandbox-images/red.Dockerfile -t $(RED_IMAGE) .

## Build all images
build: build-target build-red

# ── Local development stack ───────────────────────────────────────────────────

## Start Jentic Mini + Harbinger target + red toolbox locally
up: build
	docker compose up -d
	@echo ""
	@echo "Harbinger API : http://localhost:5000"
	@echo "Jentic Mini   : http://localhost:8900  (add credentials here)"
	@echo ""
	@echo "Run 'make shell-red' to drop into the attack container"

## Stop and remove local containers + volumes
down:
	docker compose down -v

## Open a bash shell in the red team attack container
shell-red:
	docker compose exec red bash

## Open a bash shell in the Harbinger target container
shell-target:
	docker compose exec target bash

## Tail Harbinger access log + process watcher output
logs:
	docker compose exec target tail -f /var/log/harbinger_access.log /var/log/procs.log

# ── Python ────────────────────────────────────────────────────────────────────

## Install Python dependencies
install:
	pip install -r orchestrator/requirements.txt

# ── Orchestrators ─────────────────────────────────────────────────────────────

## Run the red team pipeline (provisions Daytona sandboxes, writes findings.json)
red:
	python3 orchestrator/red_team.py

## Reset target to clean snapshot for demo replay, then run the pipeline
reset:
	python3 orchestrator/red_team.py --reset

## Run the blue team (reads findings.json, opens GitHub PRs)
blue:
	python3 orchestrator/blue_team.py

## Run full pipeline end-to-end
pipeline: red blue

# ── Push images to registry ───────────────────────────────────────────────────
# Usage: make push REGISTRY=docker.io/youruser

push: build
	docker tag $(TARGET_IMAGE) $(REGISTRY)/openclaw-target:latest
	docker tag $(RED_IMAGE)    $(REGISTRY)/openclaw-red:latest
	docker push $(REGISTRY)/openclaw-target:latest
	docker push $(REGISTRY)/openclaw-red:latest

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	docker compose down -v --remove-orphans
	docker rmi -f $(TARGET_IMAGE) $(RED_IMAGE) 2>/dev/null || true
