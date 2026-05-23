# Merkle Tree Ethereum Transaction Verifier

A Python implementation of a Merkle tree to verify Ethereum transaction inclusion — from scratch.

## What This Does

| Part       | Description                                                    |
| ---------- | -------------------------------------------------------------- |
| **Part 1** | Pure Merkle tree: build, generate proofs, verify proofs        |
| **Part 2** | Fetch real Ethereum block data via JSON-RPC                    |
| **Part 3** | Reconstruct the transactions root + end-to-end inclusion proof |

Includes all **Extension Challenges**: RLP+Keccak-256 (A), odd leaf handling (B), light client simulation (C), and historical block verification (D).

---

## Project Structure

```
ethereum-merkle-tree-verifier/
├── part1_tree.py
├── part2_fetch.py
├── part3_verify.py
├── requirements.txt
├── README.md
├── .env
├── tests/
│   └── test_merkle.py
└── venv/
```

---

## Prerequisites

- Python 3.11+
- A free Ethereum RPC endpoint from [Alchemy](https://www.alchemy.com/) or [Infura](https://www.infura.io/)
- Docker + Docker Compose (for containerized runs)

---

## Setup

### 1. Clone and install

```bash
git clone <your-repo-url>
cd ethereum-merkle-tree-verifier
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure your RPC URL

```bash
# Create .env from the template
copy .env.example .env
```

Then edit `.env` and set:

```env
RPC_URL=https://ethereum.publicnode.com
```

For a dedicated endpoint, replace it with your Alchemy or Infura URL.

---

## Running

### Option A — Python directly

```bash
# Run only Part 1 (no RPC needed — pure tree tests)
python part1_tree.py

# Run only Part 2 (fetch + inspect a block)
python part2_fetch.py

# Run only Part 3 (full verification)
python part3_verify.py
```

### Option B — Docker Compose

```bash
# Full end-to-end (requires ETH_RPC_URL in .env)
docker-compose up merkle-verifier

# Run tests only
docker-compose --profile test up merkle-tests

# Run Part 1 only (no network needed)
docker-compose --profile part1 up merkle-part1
```

### Option C — pytest

```bash
pytest tests/ -v
# With coverage
pytest tests/ -v --cov=src --cov-report=term-missing
```

---

## How It Works

### Merkle Tree

```
Items:  [alice]    [bob]      [carol]    [dave]
         │          │          │          │
Leaves: H(alice)  H(bob)    H(carol)   H(dave)
         └────┬────┘          └────┬────┘
           H(L,R)              H(L,R)
              └──────────┬──────────┘
                      Root Hash
```

A Merkle proof for `carol` (index 2) contains:

1. Sibling of carol: `H(dave)` [right]
2. Sibling of that subtree: `H(alice, bob)` [left]

The verifier computes: `H(H(H(carol), H(dave)), H(alice, bob))` and checks against root.

### Ethereum Connection

Every Ethereum block header contains a `transactionsRoot` — a single 32-byte hash that cryptographically commits to every transaction in the block. This project reconstructs that root and proves individual transaction inclusion.

---

## Key Design Decisions

| Decision                      | Rationale                                                    |
| ----------------------------- | ------------------------------------------------------------ |
| Odd leaf duplication          | Standard Merkle tree convention; prevents imbalanced trees   |
| `verify_proof` is standalone  | Matches Ethereum light client model — no access to full tree |
| SHA-256 for Option A          | Validates tree structure before tackling encoding details    |
| RLP + Keccak-256 for Option B | Matches Ethereum's actual transaction hashing                |

---

## Environment Variables

| Variable  | Required        | Description                                                    |
| --------- | --------------- | -------------------------------------------------------------- |
| `RPC_URL` | For Parts 2 & 3 | Ethereum JSON-RPC endpoint (Alchemy/Infura or public endpoint) |

**Never commit your actual API key.** The `.env` file is gitignored.

---

## Extensions Implemented

- **Extension A** — RLP + Keccak-256 hashing (in `part3_verify.py`, `hash_transaction_rlp`)
- **Extension B** — Odd leaf count handling (tested in `part3_verify.py` and `tests/`)
- **Extension C** — Light client simulation (`light_client_verify` in `part3_verify.py`)
- **Extension D** — Historical block: pass any block number to `fetch_block(rpc_url, block_number)`

---

## Running Historical Block Verification (Extension D)

```python
from src.part2_fetch import fetch_block
from src.part3_verify import prove_transaction_inclusion

# Fetch a block from ~6 months ago (approximate block number)
block = fetch_block(os.environ["ETH_RPC_URL"], 20_000_000)
prove_transaction_inclusion(block, tx_index=0)
```

---

## License

MIT
