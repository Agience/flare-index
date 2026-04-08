.PHONY: build test demo demo-compose bench shell stack-up stack-down clean

build:
	docker compose build

test:
	docker compose run --rm flare

demo:
	docker compose run --rm flare bash /work/compose/entrypoint.sh tests -k "nothing"  # noop guard
	docker compose run --rm --entrypoint "" flare python -m flare.demo

# Bring up the full multi-service stack and run the cross-process demo
# against the live ledger / storage / oracle-alice / oracle-bob services.
demo-compose:
	docker compose up -d ledger storage \
	    oracle-alice-1 oracle-alice-2 oracle-alice-3 \
	    oracle-bob-1 oracle-bob-2 oracle-bob-3
	docker compose run --rm demo
	docker compose down

stack-up:
	docker compose up -d ledger storage \
	    oracle-alice-1 oracle-alice-2 oracle-alice-3 \
	    oracle-bob-1 oracle-bob-2 oracle-bob-3

stack-down:
	docker compose down -v

bench:
	docker compose run --rm --entrypoint "" flare python bench/bench_encrypted_vs_plain.py

bench-real:
	docker compose run --rm --entrypoint "" flare python bench/bench_real_data.py

showcase:
	docker compose run --rm --entrypoint "" flare python -m flare.showcase

shell:
	docker compose run --rm --entrypoint "" flare bash

clean: stack-down
