"""FLARE showcase: real semantic search with cryptographic access control.

This is a runnable demonstration of the entire FLARE system on real
text data. Two data owners (Alice and Bob) each publish a small
hand-curated corpus on a distinct topic. A querier (Carol) submits
real natural-language questions and observes that:

  1. Without any grants she sees nothing — every encrypted cell
     remains opaque.
  2. After Alice grants her access to the cooking corpus, the same
     query returns *cooking* results semantically related to the
     question, and only cooking results.
  3. After Bob also grants access to the astronomy corpus, queries
     return whichever topic is more semantically similar — the
     embedding model picks the right one.
  4. After Alice revokes her grant, cooking results disappear
     immediately. No re-encryption, no re-indexing — only the ledger
     entry changed.

Run with:
    make showcase

The cryptographic and authorization layers are exactly the ones the
test suite exercises (multi-process via FastAPI TestClient, Ed25519
signed batch wire protocol, Shamir K=2-of-M=3 threshold oracles,
signed grants, hash-chained ledger, owner-signed storage writes,
cell-key TTLs). The only thing the showcase adds is real text and
real embeddings.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

import numpy as np
from fastapi.testclient import TestClient
from sentence_transformers import SentenceTransformer

from flare.bootstrap import bootstrap_context
from flare.crypto import fresh_master_key
from flare.identity import Identity
from flare.ledger import build_ledger_app
from flare.ledger.client import HttpLedgerClient
from flare.lightcone import Edge, LightConeGraph
from flare.oracle import (
    PeerEndpoint,
    PeerShareFetcher,
    build_oracle_app,
    split_secret,
)
from flare.oracle.client import HttpOracleClient, OracleClient
from flare.query import FlareQueryEngine
from flare.storage import build_storage_app
from flare.storage.client import HttpStorageClient
from flare.storage.memory import OracleEndpoint


# ---------------------------------------------------------------------------
# Real corpora — two distinct topics, hand-curated.
# ---------------------------------------------------------------------------

COOKING = [
    "Sous vide cooking holds food at a precise temperature in a water bath, producing exceptionally even doneness.",
    "For a medium-rare steak, sear briefly over high heat after holding the meat at 54 degrees Celsius for an hour.",
    "Maillard browning happens above about 140 degrees Celsius and is what gives seared meat its complex flavor.",
    "A roux is equal parts flour and fat cooked together; cook it longer for a darker, nuttier flavor.",
    "Salt drawn out of meat hours in advance dissolves and is reabsorbed, seasoning the interior, not just the surface.",
    "Resting cooked meat lets the muscle fibers relax so juices redistribute instead of running out when sliced.",
    "Bread dough hydration is the ratio of water to flour by weight; high-hydration doughs produce more open crumb.",
    "Sourdough relies on wild yeast and lactic acid bacteria captured from flour and air, not commercial yeast.",
    "Caramelization of sugar begins around 160 degrees Celsius and produces hundreds of distinct flavor compounds.",
    "Knife skills matter: a sharp knife is safer than a dull one because it requires less force and slips less often.",
    "Blanching vegetables briefly in boiling water then shocking them in ice water sets color and stops cooking.",
    "Emulsions like mayonnaise are oil droplets suspended in water, stabilized by lecithin from the egg yolk.",
    "Gluten development comes from kneading, which aligns the proteins glutenin and gliadin into stretchy networks.",
    "Pickling preserves vegetables by lowering pH to a level at which most spoilage organisms cannot survive.",
    "Fermenting vegetables like cabbage relies on lactic acid bacteria that produce a tangy, complex flavor over weeks.",
    "Stocks are made by simmering bones for hours; collagen breaks down into gelatin and gives the liquid body.",
    "A reduction concentrates flavors by simmering a liquid until water evaporates; do not season until after reducing.",
    "Tempering chocolate aligns the cocoa butter crystals into the form that gives finished chocolate snap and shine.",
    "Pan deglazing adds liquid to a hot pan to dissolve the browned fond, capturing flavor for sauces.",
    "Carryover cooking continues to raise internal temperature for several minutes after meat leaves heat — pull early.",
    "Brining poultry in salted water before roasting helps the meat retain moisture during cooking.",
    "Whisking egg whites traps air in protein films; cream of tartar stabilizes the foam against collapse.",
    "Pasta should be cooked until al dente — firm to the bite — and finished in the sauce so it absorbs flavor.",
    "Rice pilaf toasts the grains in fat before adding liquid, separating each grain in the finished dish.",
    "Pressure cooking raises the boiling point of water above 100 degrees Celsius, drastically shortening cook times.",
]

ASTRONOMY = [
    "The Hubble Space Telescope was launched in 1990 and has produced some of the deepest images of distant galaxies.",
    "Mars is on average about 225 million kilometers from Earth, but the distance varies as both planets orbit the Sun.",
    "Black holes are regions where gravity is so strong that not even light can escape past the event horizon.",
    "The Andromeda galaxy is the nearest large spiral galaxy to the Milky Way, about 2.5 million light-years away.",
    "A light-year is the distance that light travels in vacuum over one Julian year, about 9.46 trillion kilometers.",
    "Jupiter's Great Red Spot is a persistent anticyclonic storm that has been observed for at least 350 years.",
    "Saturn's rings are made mostly of water ice particles ranging in size from dust grains to large boulders.",
    "Pluto was reclassified from a planet to a dwarf planet by the International Astronomical Union in 2006.",
    "The James Webb Space Telescope observes primarily in the infrared and uses a 6.5-meter segmented mirror.",
    "Neutron stars form from the collapsed cores of massive stars and are among the densest objects in the universe.",
    "A solar eclipse occurs when the Moon passes between the Earth and the Sun, casting a shadow on Earth's surface.",
    "The cosmic microwave background is the afterglow of the Big Bang and pervades the entire observable universe.",
    "Exoplanets are planets that orbit stars other than the Sun; thousands have been confirmed since the first in 1992.",
    "Stellar fusion converts hydrogen into helium in stellar cores, releasing energy and supporting the star against gravity.",
    "Mercury, the closest planet to the Sun, has the most eccentric orbit of any planet in the Solar System.",
    "The Voyager 1 spacecraft, launched in 1977, has crossed the heliopause and is now in interstellar space.",
    "Venus has a runaway greenhouse atmosphere of carbon dioxide and surface temperatures around 460 degrees Celsius.",
    "Pulsars are rapidly rotating neutron stars whose magnetic poles emit beams of radio waves like cosmic lighthouses.",
    "The Milky Way galaxy contains an estimated 100 to 400 billion stars and a supermassive black hole at its center.",
    "An astronomical unit is the average distance from the Earth to the Sun, about 150 million kilometers.",
    "Comets are icy bodies that develop visible tails of gas and dust when they pass close to the Sun.",
    "The asteroid belt between Mars and Jupiter contains millions of rocky bodies left over from the early Solar System.",
    "A galaxy's rotation curve indicates the presence of dark matter — outer stars orbit faster than visible mass predicts.",
    "Telescopes collect light over a large aperture; bigger mirrors gather more light and resolve finer detail.",
    "The Drake equation estimates the number of communicating civilizations in our galaxy by multiplying several factors.",
]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

THRESHOLD_K = 2
THRESHOLD_M = 3


def _embed(model: SentenceTransformer, texts: list[str]) -> np.ndarray:
    """Compute L2-normalized embeddings (so dot product == cosine similarity)."""
    v = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return np.asarray(v, dtype=np.float32)


def _build_threshold_replicas(owner: Identity, ledger_app, label: str):
    master = fresh_master_key()
    oracle_ids = [Identity.generate() for _ in range(THRESHOLD_M)]
    shares = split_secret(master, k=THRESHOLD_K, m=THRESHOLD_M)
    base_urls = [f"http://oracle-{label}-{i+1}.local" for i in range(THRESHOLD_M)]
    apps, clients, cores = [], [], []
    for i in range(THRESHOLD_M):
        ledger_client = HttpLedgerClient(client=TestClient(ledger_app))
        app = build_oracle_app(
            owner_did=owner.did, ledger_client=ledger_client,
            share=shares[i], threshold_k=THRESHOLD_K,
            peer_share_fetcher=None,
            oracle_identity=oracle_ids[i],
            allowed_coord_dids={oid.did for oid in oracle_ids},
        )
        apps.append(app)
        clients.append(TestClient(app))
        cores.append(app.state.core)
    for i in range(THRESHOLD_M):
        peers = [
            PeerEndpoint(oracle_did=oracle_ids[j].did, client=clients[j])
            for j in range(THRESHOLD_M) if j != i
        ]
        cores[i]._peer_share_fetcher = PeerShareFetcher(  # noqa: SLF001
            coord_identity=oracle_ids[i], peers=peers, needed=THRESHOLD_K - 1,
        )
    return master, oracle_ids, base_urls, clients, apps


def _print_results(label: str, query: str, hits, id_to_text: dict[int, str], expected: str | None):
    print(f"\n  query: {query!r}")
    if not hits:
        print("    (no results)")
        return
    for h in hits[:3]:
        text = id_to_text.get((h.context_id, h.vector_id), "<unknown>")
        marker = ""
        if expected and h.context_id == expected:
            marker = "  [from expected corpus]"
        print(f"    [{h.score:+.3f}] {text[:90]}{'...' if len(text) > 90 else ''}{marker}")


def main() -> None:
    print("=" * 78)
    print("FLARE showcase — real semantic search with cryptographic access control")
    print("=" * 78)

    print("\n[1/7] Loading embedding model (sentence-transformers/all-MiniLM-L6-v2)...")
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    dim = model.get_sentence_embedding_dimension()
    print(f"      embedding dimension = {dim}")

    print(f"\n[2/7] Embedding corpora ({len(COOKING)} cooking, {len(ASTRONOMY)} astronomy)...")
    cooking_vecs = _embed(model, COOKING)
    astronomy_vecs = _embed(model, ASTRONOMY)
    cooking_ids = np.arange(len(COOKING), dtype=np.int64)
    astronomy_ids = np.arange(len(ASTRONOMY), dtype=np.int64)
    id_to_text = {
        ("cooking", i): COOKING[i] for i in range(len(COOKING))
    }
    id_to_text.update({
        ("astronomy", i): ASTRONOMY[i] for i in range(len(ASTRONOMY))
    })

    print("\n[3/7] Generating identities (Alice, Bob, Carol — all did:key, no central CA)...")
    alice = Identity.generate()
    bob = Identity.generate()
    carol = Identity.generate()
    print(f"      alice  = {alice.did[:48]}...")
    print(f"      bob    = {bob.did[:48]}...")
    print(f"      carol  = {carol.did[:48]}...")

    print("\n[4/7] Bringing up the FLARE stack (ledger + storage + 6 threshold oracles)...")
    ledger_app = build_ledger_app()
    ledger = HttpLedgerClient(client=TestClient(ledger_app))
    storage_app = build_storage_app()
    storage = HttpStorageClient(client=TestClient(storage_app))

    a_master, a_oids, a_urls, a_clients, a_apps = _build_threshold_replicas(alice, ledger_app, "alice")
    b_master, b_oids, b_urls, b_clients, b_apps = _build_threshold_replicas(bob, ledger_app, "bob")

    a_url_to_client = dict(zip(a_urls, a_clients))
    b_url_to_client = dict(zip(b_urls, b_clients))

    def resolve(endpoint: str) -> OracleClient:
        if endpoint in a_url_to_client:
            return HttpOracleClient(client=a_url_to_client[endpoint])
        if endpoint in b_url_to_client:
            return HttpOracleClient(client=b_url_to_client[endpoint])
        raise KeyError(endpoint)

    print(f"      threshold mode: K={THRESHOLD_K} of M={THRESHOLD_M}")
    print(f"      alice oracle replicas: {[u for u in a_urls]}")
    print(f"      bob   oracle replicas: {[u for u in b_urls]}")

    print("\n[5/7] Bootstrapping contexts — owners encrypt their corpora and publish.")
    cooking_result = bootstrap_context(
        storage=storage, context_id="cooking",
        owner_identity=alice,
        oracle_endpoints=[OracleEndpoint(url=u, oracle_did=oid.did)
                          for u, oid in zip(a_urls, a_oids)],
        vectors=cooking_vecs, ids=cooking_ids,
        master_key=a_master, nlist=4,
        ledger_client=ledger,
    )
    astronomy_result = bootstrap_context(
        storage=storage, context_id="astronomy",
        owner_identity=bob,
        oracle_endpoints=[OracleEndpoint(url=u, oracle_did=oid.did)
                          for u, oid in zip(b_urls, b_oids)],
        vectors=astronomy_vecs, ids=astronomy_ids,
        master_key=b_master, nlist=4,
        ledger_client=ledger,
    )
    # Inject encrypted centroids and wrapped CEKs into every oracle replica.
    for app in a_apps:
        app.state.core.store_encrypted_centroids(
            "cooking", cooking_result.encrypted_centroids,
        )
        for cell_ref, wrapped in cooking_result.wrapped_ceks.items():
            app.state.core.store_wrapped_cek(cell_ref, wrapped)
    for app in b_apps:
        app.state.core.store_encrypted_centroids(
            "astronomy", astronomy_result.encrypted_centroids,
        )
        for cell_ref, wrapped in astronomy_result.wrapped_ceks.items():
            app.state.core.store_wrapped_cek(cell_ref, wrapped)
    print(f"      cooking:   {len(COOKING)} docs encrypted into per-cluster cells under Alice's master key")
    print(f"      astronomy: {len(ASTRONOMY)} docs encrypted into per-cluster cells under Bob's master key")

    graph = LightConeGraph()
    graph.add_context("cooking")
    graph.add_context("astronomy")
    graph.add_edge(Edge(alice.did, "cooking", "owns"))
    graph.add_edge(Edge(bob.did, "astronomy", "owns"))

    engine = FlareQueryEngine(storage=storage, lightcone=graph, oracle_resolver=resolve)
    # Use real wall-clock time so it agrees with the wire layer's time.time_ns().
    now = datetime.utcnow()

    questions = [
        ("What temperature should I use for medium-rare steak?", "cooking"),
        ("How far is Mars from Earth?", "astronomy"),
        ("How does sourdough fermentation work?", "cooking"),
        ("What is the cosmic microwave background?", "astronomy"),
    ]

    def run(label: str, principal: Identity):
        print(f"\n  --- {label} ---")
        for q, expected in questions:
            q_vec = _embed(model, [q])[0]
            hits, trace = engine.search(principal, q_vec, k=3, nprobe=8, now=now)
            print(f"\n  query: {q!r}")
            print(f"    [trace] candidates={len(trace.candidate_cells)} "
                  f"authorized={sorted(trace.authorized_contexts)} "
                  f"filtered={len(trace.light_cone_filtered)} "
                  f"granted={len(trace.oracle_granted)} "
                  f"denied={len(trace.oracle_denied)} "
                  f"decrypted={trace.decrypted_cells}")
            if not hits:
                print("    (no results)")
                continue
            for h in hits[:3]:
                text = id_to_text.get((h.context_id, h.vector_id), "<unknown>")
                marker = ""
                if expected and h.context_id == expected:
                    marker = "  [from expected corpus]"
                print(f"    [{h.score:+.3f}] {text[:90]}{'...' if len(text) > 90 else ''}{marker}")

    print("\n[6/7] Carol queries — no grants exist yet.")
    print("      Expected: Carol sees nothing. Every encrypted cell stays opaque.")
    run("Carol, no access", carol)

    print("\n[7/7] Alice grants Carol read on the cooking corpus.")
    grant_a = ledger.add_grant(
        grantor_identity=alice, grantee=carol.did,
        context_id="cooking", issued_at=now,
    )
    graph.add_edge(Edge(carol.did, "cooking", "granted"))
    print(f"      grant id = {grant_a.grant_id[:8]}...  (signed by Alice, appended to ledger chain)")
    print("      Expected: cooking questions return cooking docs; astronomy questions return nothing.")
    run("Carol, after Alice's grant", carol)

    print("\n      Bob ALSO grants Carol read on the astronomy corpus.")
    grant_b = ledger.add_grant(
        grantor_identity=bob, grantee=carol.did,
        context_id="astronomy", issued_at=now,
    )
    graph.add_edge(Edge(carol.did, "astronomy", "granted"))
    print(f"      grant id = {grant_b.grant_id[:8]}...  (signed by Bob)")
    print("      Expected: every question returns the topically-correct corpus, picked by the embedding model.")
    run("Carol, after both grants", carol)

    print("\n      Alice REVOKES Carol's grant. No re-encryption. No key rotation.")
    revoke_at = now + timedelta(seconds=2)
    ledger.revoke(grant_a, grantor_identity=alice, revoked_at=revoke_at)
    engine.invalidate_cell_keys()  # drop cached pre-revoke keys for instant effect
    print(f"      revoke signed by Alice and appended to ledger chain")
    print("      Expected: cooking results vanish; astronomy still works.")
    run("Carol, after Alice's revoke", carol)

    print("\n" + "=" * 78)
    print("Showcase complete.")
    print()
    print("What you just saw:")
    print("  - Real text was embedded with a real model (all-MiniLM-L6-v2, 384-d).")
    print("  - The embeddings were partitioned per-context and encrypted under per-cell")
    print("    keys derived from each owner's master key (HKDF-SHA256 + AES-256-GCM).")
    print("  - Each query was authorized by the light-cone graph, then centroid maps")
    print("    were fetched from the oracle (encrypted at rest, delivered via ECIES),")
    print("    then routed, then key-issued by a Shamir K=2-of-M=3 threshold oracle")
    print("    (3 replicas per owner cooperating via signed peer protocol).")
    print("  - Every oracle response was Ed25519-signed, ECIES-encrypted, and TTL-bounded.")
    print("  - Grants are signed and live on a hash-chained ledger; revocation is a single")
    print("    signed ledger entry.  No re-encryption.  No key rotation.  No coordination.")
    print()
    print("All four FLARE security properties were exercised end-to-end on real data:")
    print("  1. Authorization gating  (Carol with no grant sees nothing)")
    print("  2. Topical recall        (semantic similarity picks the right corpus)")
    print("  3. Owner-scoped grants   (each owner controls their own context independently)")
    print("  4. Instant revocation    (one signed ledger entry hides Alice's data)")
    print("=" * 78)


if __name__ == "__main__":
    main()
