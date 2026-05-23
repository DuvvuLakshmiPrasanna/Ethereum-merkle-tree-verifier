"""
Main entry point — runs all three parts in sequence.
Usage:
    python main.py
    ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY python main.py
"""

import os
import sys

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))


def main():
    print("\n" + "█" * 60)
    print("  MERKLE TREE ETHEREUM TRANSACTION VERIFIER")
    print("  Build a Merkle Tree in Python to Verify Ethereum Transactions")
    print("█" * 60)

    # ── PART 1 ────────────────────────────────────────────────────────────
    print("\n\n>>> Running Part 1: Merkle Tree Implementation & Tests")
    from part1_tree import run_tests
    run_tests()

    # ── PARTS 2 & 3 ───────────────────────────────────────────────────────
    rpc_url = os.environ.get("ETH_RPC_URL")
    if not rpc_url:
        print("\n" + "=" * 60)
        print("PARTS 2 & 3 SKIPPED")
        print("=" * 60)
        print("ETH_RPC_URL not set — skipping live Ethereum interaction.")
        print("Set it to run the full end-to-end verification:")
        print("  export ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY")
        print("  python main.py")
        print("\nPart 1 (pure Merkle tree logic) completed successfully. ✓")
        return

    print("\n\n>>> Running Part 2: Fetch Ethereum Block")
    from part2_fetch import run_fetch_demo
    run_fetch_demo(rpc_url)

    print("\n\n>>> Running Part 3: Reconstruct & Verify")
    from part3_verify import main as part3_main
    part3_main()

    print("\n\n" + "█" * 60)
    print("  ALL PARTS COMPLETE ✓")
    print("█" * 60 + "\n")


if __name__ == "__main__":
    main()
