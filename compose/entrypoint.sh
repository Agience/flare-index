#!/usr/bin/env bash
# Shared entrypoint for all docker-compose services.
#
# Usage: entrypoint.sh ROLE [args...]
set -euo pipefail

ROLE="${1:-}"
shift || true

wait_for_secrets() {
    local f=/secrets/phase3.env
    for _ in $(seq 1 50); do
        if [[ -f "$f" ]]; then
            # shellcheck disable=SC1090
            set -a; source "$f"; set +a
            return 0
        fi
        sleep 0.2
    done
    echo "ERROR: $f never appeared" >&2
    exit 2
}

# Set the threshold-mode env vars for an oracle replica of `OWNER` (alice|bob)
# at index `IDX` (1..3). Peers are the other two replicas of the same owner;
# allowed coord DIDs are all three replicas of the same owner (so any of them
# can act as the coordinator and ask the others for shares).
configure_oracle() {
    local owner_upper="$1"   # ALICE or BOB
    local idx="$2"           # 1, 2, or 3

    case "$owner_upper" in
        ALICE)
            export OWNER_DID="$ALICE_DID"
            export PEER_HOST_BASE="oracle-alice"
            ;;
        BOB)
            export OWNER_DID="$BOB_DID"
            export PEER_HOST_BASE="oracle-bob"
            ;;
        *)
            echo "configure_oracle: unknown owner $owner_upper" >&2; exit 2 ;;
    esac

    eval "export ORACLE_DID=\$${owner_upper}_ORACLE_${idx}_DID"
    # Phase 4: load signing key + Shamir share from a passphrase-encrypted
    # sealed file instead of raw env vars. The legacy env-var path
    # (ORACLE_SIGNING_KEY_HEX + ORACLE_SHARE) is still supported by
    # services_main.py and is exercised by tests.
    local owner_lower
    case "$owner_upper" in
        ALICE) owner_lower="alice" ;;
        BOB)   owner_lower="bob" ;;
    esac
    export SEALED_KEY_FILE="/secrets/sealed/${owner_lower}_oracle_${idx}.bin"
    export SEALED_KEY_PASSPHRASE_FILE="/secrets/passphrase"
    export THRESHOLD_K="$FLARE_THRESHOLD_K"

    # Build PEER_DIDS / PEER_URLS / ALLOWED_COORD_DIDS from the other replicas.
    local peer_dids=""
    local peer_urls=""
    local allowed=""
    for i in 1 2 3; do
        local d_var="${owner_upper}_ORACLE_${i}_DID"
        eval "local d=\$$d_var"
        # Allowed coord list: all three replicas (any can play coordinator).
        if [[ -z "$allowed" ]]; then
            allowed="$d"
        else
            allowed="$allowed,$d"
        fi
        if [[ "$i" != "$idx" ]]; then
            local url="http://${PEER_HOST_BASE}-${i}:8001"
            if [[ -z "$peer_dids" ]]; then
                peer_dids="$d"
                peer_urls="$url"
            else
                peer_dids="$peer_dids,$d"
                peer_urls="$peer_urls,$url"
            fi
        fi
    done
    export PEER_DIDS="$peer_dids"
    export PEER_URLS="$peer_urls"
    export ALLOWED_COORD_DIDS="$allowed"
    export PORT="8001"
    : "${LEDGER_URL:?LEDGER_URL must be set}"
}

case "$ROLE" in
    secrets)
        exec python -m compose.generate_secrets "$@"
        ;;
    ledger)
        exec python -m flare.services_main ledger
        ;;
    storage)
        exec python -m flare.services_main storage
        ;;
    oracle-alice-1) wait_for_secrets; configure_oracle ALICE 1; exec python -m flare.services_main oracle ;;
    oracle-alice-2) wait_for_secrets; configure_oracle ALICE 2; exec python -m flare.services_main oracle ;;
    oracle-alice-3) wait_for_secrets; configure_oracle ALICE 3; exec python -m flare.services_main oracle ;;
    oracle-bob-1)   wait_for_secrets; configure_oracle BOB 1;   exec python -m flare.services_main oracle ;;
    oracle-bob-2)   wait_for_secrets; configure_oracle BOB 2;   exec python -m flare.services_main oracle ;;
    oracle-bob-3)   wait_for_secrets; configure_oracle BOB 3;   exec python -m flare.services_main oracle ;;
    demo)
        wait_for_secrets
        exec python -m flare.demo_compose "$@"
        ;;
    tests)
        exec pytest -q "$@"
        ;;
    *)
        echo "unknown role: $ROLE" >&2
        exit 2
        ;;
esac
