"""Run the verifier demos in a single entrypoint for Docker and local usage."""

import os

from dotenv import load_dotenv

from part1_tree import MerkleTree, verify_proof
from part2_fetch import get_rpc_url, run_fetch_demo
from part3_verify import main as run_part3

load_dotenv()


def run_part1_smoke_test() -> None:
    tree = MerkleTree([b"alpha", b"beta", b"gamma"])
    proof = tree.get_proof(2)
    if not verify_proof(b"gamma", proof, tree.root):
        raise RuntimeError("Part 1 smoke test failed")
    print("[PART 1] Smoke test passed: Merkle proof verified successfully.")


def main() -> None:
    run_part1_smoke_test()

    rpc_url = os.environ.get("ETH_RPC_URL") or os.environ.get("RPC_URL")
    if not rpc_url:
        print("[PART 2/3] ETH_RPC_URL not set; skipping network demo.")
        return

    run_fetch_demo(rpc_url)
    run_part3()


if __name__ == "__main__":
    main()
