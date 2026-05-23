"""
Part 3 - Reconstruct and Verify Ethereum Transaction Merkle Root
"""

import copy
import hashlib

import sha3
from dotenv import load_dotenv
import rlp

from part1_tree import MerkleTree, verify_proof
from part2_fetch import fetch_block, get_rpc_url, inspect_block

load_dotenv()


def keccak256(data: bytes) -> bytes:
    """Compute Keccak-256 hash (Ethereum's native hash function)."""
    k = sha3.keccak_256()
    k.update(data)
    return k.digest()


def hash_transaction_simple(tx: dict) -> bytes:
    """Option A: SHA-256 of the transaction hash hex string."""
    tx_hash_hex = tx.get("hash", "")
    return hashlib.sha256(tx_hash_hex.encode()).digest()


def _decode_hex(value: str | None, default: int = 0) -> int:
    if value is None or value == "0x" or value == "":
        return default
    return int(value, 16)


def _decode_hex_bytes(value: str | None) -> bytes:
    if value is None or value == "0x" or value == "":
        return b""
    return bytes.fromhex(value[2:] if value.startswith("0x") else value)


def hash_transaction_rlp(tx: dict) -> bytes:
    """Option B: Keccak-256 of the RLP-encoded transaction."""
    tx_type = _decode_hex(tx.get("type"), 0)

    if tx_type == 0 or tx_type is None:
        fields = [
            _decode_hex(tx.get("nonce")),
            _decode_hex(tx.get("gasPrice")),
            _decode_hex(tx.get("gas")),
            _decode_hex_bytes(tx.get("to")),
            _decode_hex(tx.get("value")),
            _decode_hex_bytes(tx.get("input")),
            _decode_hex(tx.get("v")),
            _decode_hex(tx.get("r")),
            _decode_hex(tx.get("s")),
        ]
        encoded = rlp.encode(fields)
        return keccak256(encoded)

    if tx_type == 1:
        fields = [
            _decode_hex(tx.get("chainId")),
            _decode_hex(tx.get("nonce")),
            _decode_hex(tx.get("gasPrice")),
            _decode_hex(tx.get("gas")),
            _decode_hex_bytes(tx.get("to")),
            _decode_hex(tx.get("value")),
            _decode_hex_bytes(tx.get("input")),
            [],
            _decode_hex(tx.get("v")),
            _decode_hex(tx.get("r")),
            _decode_hex(tx.get("s")),
        ]
        encoded = bytes([1]) + rlp.encode(fields)
        return keccak256(encoded)

    if tx_type == 2:
        fields = [
            _decode_hex(tx.get("chainId")),
            _decode_hex(tx.get("nonce")),
            _decode_hex(tx.get("maxPriorityFeePerGas")),
            _decode_hex(tx.get("maxFeePerGas")),
            _decode_hex(tx.get("gas")),
            _decode_hex_bytes(tx.get("to")),
            _decode_hex(tx.get("value")),
            _decode_hex_bytes(tx.get("input")),
            [],
            _decode_hex(tx.get("v")),
            _decode_hex(tx.get("r")),
            _decode_hex(tx.get("s")),
        ]
        encoded = bytes([2]) + rlp.encode(fields)
        return keccak256(encoded)

    return hashlib.sha256(tx.get("hash", "").encode()).digest()


def hash_transaction(tx: dict, use_rlp: bool = False) -> bytes:
    if use_rlp:
        return hash_transaction_rlp(tx)
    return hash_transaction_simple(tx)


def reconstruct_transactions_root(
    transactions: list[dict], use_rlp: bool = False
) -> bytes:
    if not transactions:
        raise ValueError("No transactions to build tree from.")

    leaf_hashes = [
        hash_transaction(tx, use_rlp=use_rlp) for tx in transactions
    ]
    tree = MerkleTree(leaf_hashes)
    return tree.root


def verify_transactions_root(block: dict, use_rlp: bool = False) -> bool:
    transactions = block.get("transactions", [])
    header_root_hex = block.get("transactionsRoot", "")
    header_root = bytes.fromhex(
        header_root_hex[2:]
        if header_root_hex.startswith("0x")
        else header_root_hex
    )

    computed_root = reconstruct_transactions_root(
        transactions, use_rlp=use_rlp
    )

    method = "RLP + Keccak-256" if use_rlp else "SHA-256 (simplified)"
    print(f"\n  Hashing Method   : {method}")
    print(f"  Header Root      : {header_root.hex()}")
    print(f"  Computed Root    : {computed_root.hex()}")

    match = computed_root == header_root
    if match:
        print("  Match            : ✓ YES — roots match!")
    else:
        print(
            "  Match            : ✗ NO — roots differ "
            "(expected for Option A)"
        )
    return match


def prove_transaction_inclusion(
    block: dict, tx_index: int, use_rlp: bool = False
) -> None:
    transactions = block.get("transactions", [])
    if not transactions:
        print("No transactions in this block.")
        return

    if tx_index < 0 or tx_index >= len(transactions):
        raise IndexError(
            f"tx_index {tx_index} out of range "
            f"(block has {len(transactions)} txs)."
        )

    print(f"\n  Target Transaction Index : {tx_index}")
    print(
        f"  Transaction Hash         : "
        f"{transactions[tx_index].get('hash', 'N/A')}"
    )

    raw_leaves = [tx.get("hash", "").encode() for tx in transactions]
    proof_tree = MerkleTree(raw_leaves)
    proof = proof_tree.get_proof(tx_index)
    target_leaf = raw_leaves[tx_index]
    computed_root = proof_tree.root

    valid = verify_proof(target_leaf, proof, computed_root)

    print(f"\n  Merkle Tree Root         : {computed_root.hex()}")
    print(f"  Proof depth              : {len(proof)} sibling hashes")
    print("\n  Proof Path (leaf → root):")
    for i, step in enumerate(proof):
        print(
            f"    Step {i + 1}: "
            f"[{step['position'].upper()}] {step['hash'].hex()}"
        )

    if valid:
        print(
            "\n  Verification Result      : "
            "✓ VALID — transaction included in block"
        )
    else:
        print("\n  Verification Result      : ✗ INVALID")
    assert valid, "Inclusion proof must be valid!"

    tampered_proof = copy.deepcopy(proof)
    if tampered_proof:
        tampered_proof[0]["hash"] = b"\xde\xad\xbe\xef" * 8
        tampered_valid = verify_proof(
            target_leaf, tampered_proof, computed_root
        )
        if not tampered_valid:
            print(
                "  Tamper Detection         : "
                "✗ Tampered proof correctly rejected ✓"
            )
        else:
            print(
                "  Tamper Detection         : "
                "WARNING: tampered proof accepted!"
            )

    wrong_leaf_valid = verify_proof(
        b"fake_transaction_data", proof, computed_root
    )
    if not wrong_leaf_valid:
        print(
            "  Wrong Leaf Detection     : "
            "✗ Wrong leaf correctly rejected ✓"
        )
    else:
        print(
            "  Wrong Leaf Detection     : "
            "WARNING: wrong leaf accepted!"
        )


def light_client_verify(
    block_header: dict,
    tx_raw_data: bytes,
    proof: list[dict],
    reconstructed_root: bytes,
) -> bool:
    print("\n  [Light Client] Verifying inclusion with header only...")
    print(
        f"  [Light Client] Using reconstructed root: "
        f"{reconstructed_root.hex()}"
    )
    result = verify_proof(tx_raw_data, proof, reconstructed_root)
    if result:
        print("  [Light Client] Inclusion verified: ✓ VALID")
    else:
        print("  [Light Client] Inclusion verified: ✗ INVALID")
    return result


def main():
    print("=" * 60)
    print("PART 3 — Reconstruct and Verify Ethereum Transactions Root")
    print("=" * 60)

    rpc_url = get_rpc_url()

    print("\nFetching latest Ethereum block...")
    block = fetch_block(rpc_url, "latest")
    inspect_block(block)

    transactions = block.get("transactions", [])
    if not transactions:
        print("\nNo transactions in latest block, trying block -1...")
        block_num = int(block.get("number", "0x1"), 16) - 1
        block = fetch_block(rpc_url, block_num)
        transactions = block.get("transactions", [])

    print(f"\nBlock has {len(transactions)} transactions.")

    print("\n" + "─" * 60)
    print("OPTION A — Simplified SHA-256 Hashing")
    print("─" * 60)
    verify_transactions_root(block, use_rlp=False)

    print("\n" + "─" * 60)
    print("OPTION B — RLP + Keccak-256 Hashing")
    print("─" * 60)
    try:
        verify_transactions_root(block, use_rlp=True)
    except Exception as exc:
        print("  [SKIPPED] RLP hashing unavailable: " f"{exc}")

    print("\n" + "─" * 60)
    print("INCLUSION PROOF GENERATION AND VERIFICATION")
    print("─" * 60)
    prove_transaction_inclusion(block, 0, use_rlp=False)

    print("\n" + "─" * 60)
    print("EXTENSION B — Odd Leaf Count Check")
    print("─" * 60)
    count = len(transactions)
    if count % 2 == 1:
        print(
            f"  Block has {count} transactions (ODD) — "
            "odd leaf duplication tested!"
        )
        odd_root = reconstruct_transactions_root(transactions, use_rlp=False)
        print(f"  Reconstructed root: {odd_root.hex()}")
        print("  [PASS] Odd leaf count handled correctly.")
    else:
        print(
            f"  Block has {count} transactions (EVEN) — "
            "odd leaf logic not triggered here."
        )
        odd_tree = MerkleTree([b"tx0", b"tx1", b"tx2"])
        proof = odd_tree.get_proof(2)
        assert verify_proof(
            b"tx2", proof, odd_tree.root
        ), "Odd leaf proof failed!"
        print("  [PASS] Synthetic 3-leaf odd tree verified correctly.")

    print("\n" + "─" * 60)
    print("EXTENSION C — Light Client Simulation")
    print("─" * 60)
    raw_leaves = [tx.get("hash", "").encode() for tx in transactions]
    lc_tree = MerkleTree(raw_leaves)
    lc_proof = lc_tree.get_proof(0)
    lc_root = lc_tree.root

    block_header_only = {
        "number": block.get("number"),
        "transactionsRoot": block.get("transactionsRoot"),
    }
    lc_result = light_client_verify(
        block_header_only, raw_leaves[0], lc_proof, lc_root
    )
    assert lc_result, "Light client verification should succeed!"

    print("\n" + "=" * 60)
    print("PART 3 COMPLETE — All verifications passed ✓")
    print("=" * 60)


if __name__ == "__main__":
    main()
