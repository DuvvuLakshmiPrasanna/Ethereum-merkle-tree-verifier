"""
Part 2 - Fetch Real Ethereum Data
Interacts with Ethereum JSON-RPC endpoint to retrieve block and
transaction data.
"""

import os

import requests
from dotenv import load_dotenv

load_dotenv()


def get_rpc_url() -> str:
    rpc_url = os.environ.get("RPC_URL") or os.environ.get("ETH_RPC_URL")
    if not rpc_url:
        raise EnvironmentError(
            "RPC_URL or ETH_RPC_URL environment variable not set. "
            "Please add a valid Ethereum JSON-RPC endpoint to .env"
        )
    return rpc_url


def fetch_block(rpc_url: str, block_number: int | str = "latest") -> dict:
    """
    Fetch a full block (with transactions) from an Ethereum JSON-RPC endpoint.
    Returns the raw block dict including transactionsRoot and the transactions
    list. block_number can be an integer or "latest".
    """
    block_param = (
        hex(block_number) if isinstance(block_number, int) else block_number
    )

    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [block_param, True],
        "id": 1,
    }

    response = requests.post(
        rpc_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")

    block = data.get("result")
    if block is None:
        raise RuntimeError(f"Block {block_number} not found.")

    return block


def fetch_transaction_proof(rpc_url: str, tx_hash: str) -> dict:
    """
    Fetch transaction receipt (used as a proxy for inclusion evidence).
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash],
        "id": 1,
    }

    response = requests.post(
        rpc_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")

    receipt = data.get("result")
    if receipt is None:
        raise RuntimeError(f"Transaction {tx_hash} not found.")

    return receipt


def inspect_block(block: dict) -> None:
    """Print key information from a fetched block."""
    print("=" * 60)
    print("BLOCK INSPECTION")
    print("=" * 60)

    block_num = int(block.get("number", "0x0"), 16)
    timestamp = int(block.get("timestamp", "0x0"), 16)
    tx_count = len(block.get("transactions", []))
    tx_root = block.get("transactionsRoot", "N/A")
    state_root = block.get("stateRoot", "N/A")
    miner = block.get("miner", "N/A")
    gas_used = int(block.get("gasUsed", "0x0"), 16)
    gas_limit = int(block.get("gasLimit", "0x0"), 16)
    base_fee = block.get("baseFeePerGas")

    print(f"  Block Number     : {block_num} ({block.get('number')})")
    print(f"  Timestamp        : {timestamp} (Unix)")
    print(f"  Miner/Validator  : {miner}")
    print(f"  Transaction Count: {tx_count}")
    print(f"  Gas Used         : {gas_used:,} / {gas_limit:,}")
    if base_fee:
        print(f"  Base Fee (Gwei)  : {int(base_fee, 16) / 1e9:.4f}")
    print(f"\n  transactionsRoot : {tx_root}")
    print(f"  stateRoot        : {state_root}")

    if tx_count > 0:
        print(
            f"\n  First Transaction Hash : "
            f"{block['transactions'][0].get('hash', 'N/A')}"
        )
        if tx_count > 1:
            print(
                f"  Last  Transaction Hash : "
                f"{block['transactions'][-1].get('hash', 'N/A')}"
            )

    print("=" * 60)


def run_fetch_demo(rpc_url: str) -> dict:
    """Fetch a block and inspect it. Returns the block for use in Part 3."""
    print("\n" + "=" * 60)
    print("PART 2 — Fetch Ethereum Block")
    print("=" * 60)

    print("\nFetching latest Ethereum block...")
    block = fetch_block(rpc_url, "latest")
    inspect_block(block)

    return block


if __name__ == "__main__":
    block = run_fetch_demo(get_rpc_url())
    print(
        f"\nBlock fetched successfully with "
        f"{len(block.get('transactions', []))} transactions."
    )
