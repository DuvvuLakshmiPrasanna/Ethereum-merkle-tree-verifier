"""
Part 1 - Merkle Tree Implementation in Python
Pure DSA: No blockchain interaction.
"""

import hashlib
from dataclasses import dataclass, field


def sha256_pair(left: bytes, right: bytes) -> bytes:
    """Hash two child digests together to produce a parent node hash."""
    return hashlib.sha256(left + right).digest()


@dataclass
class MerkleNode:
    hash: bytes
    left: "MerkleNode | None" = field(default=None, repr=False)
    right: "MerkleNode | None" = field(default=None, repr=False)


class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        """
        Build a Merkle tree from a list of raw data items.
        Each item is hashed to form a leaf node.
        If the number of leaves is odd, duplicate the last leaf
        (standard convention).
        """
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf.")

        self._leaf_nodes: list[MerkleNode] = [
            MerkleNode(hash=hashlib.sha256(leaf).digest())
            for leaf in leaves
        ]
        self._root_node: MerkleNode = self._build(list(self._leaf_nodes))

    def _build(self, nodes: list[MerkleNode]) -> MerkleNode:
        """
        Recursively pair up nodes and hash each pair until one root remains.
        """
        if len(nodes) == 1:
            return nodes[0]

        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        next_level: list[MerkleNode] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1]
            parent_hash = sha256_pair(left.hash, right.hash)
            parent = MerkleNode(hash=parent_hash, left=left, right=right)
            next_level.append(parent)

        return self._build(next_level)

    @property
    def root(self) -> bytes:
        """Return the Merkle root hash."""
        return self._root_node.hash

    def get_proof(self, index: int) -> list[dict]:
        """
        Generate a Merkle proof for the leaf at the given index.
        Returns a list of {"hash": bytes, "position": "left" | "right"} dicts,
        ordered from leaf-level sibling up to the child of the root.
        """
        if index < 0 or index >= len(self._leaf_nodes):
            raise IndexError(
                f"Index {index} is out of range for "
                f"{len(self._leaf_nodes)} leaves."
            )

        proof: list[dict] = []
        current_level = list(self._leaf_nodes)

        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

            if index % 2 == 0:
                sibling_index = index + 1
                proof.append(
                    {
                        "hash": current_level[sibling_index].hash,
                        "position": "right",
                    }
                )
            else:
                sibling_index = index - 1
                proof.append(
                    {
                        "hash": current_level[sibling_index].hash,
                        "position": "left",
                    }
                )

            next_level: list[MerkleNode] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                parent_hash = sha256_pair(left.hash, right.hash)
                next_level.append(
                    MerkleNode(hash=parent_hash, left=left, right=right)
                )

            index = index // 2
            current_level = next_level

        return proof


def verify_proof(
    leaf_data: bytes,
    proof: list[dict],
    expected_root: bytes,
) -> bool:
    """
    Verify a Merkle proof without access to the full tree.
    Hash the leaf, then iteratively combine with each sibling
    hash in the proof. Return True if the recomputed root matches
    expected_root.
    """
    current_hash = hashlib.sha256(leaf_data).digest()

    for step in proof:
        sibling_hash = step["hash"]
        position = step["position"]

        if position == "right":
            current_hash = sha256_pair(
                current_hash,
                sibling_hash,
            )
        elif position == "left":
            current_hash = sha256_pair(
                sibling_hash,
                current_hash,
            )
        else:
            raise ValueError(
                f"Invalid position: {position}. "
                "Must be 'left' or 'right'."
            )

    return current_hash == expected_root


def run_tests():
    """Run local tests to verify the implementation."""
    print("=" * 60)
    print("PART 1 — Merkle Tree Tests")
    print("=" * 60)

    items = [b"alice", b"bob", b"carol", b"dave"]
    tree = MerkleTree(items)

    print(f"\n[Test 1] Tree root (4 leaves): {tree.root.hex()}")

    proof = tree.get_proof(2)
    result = verify_proof(b"carol", proof, tree.root)
    assert result, "Proof for 'carol' should be valid!"
    print("[PASS] Proof for 'carol' (index 2) verified successfully.")

    tampered_leaf = not verify_proof(b"mallory", proof, tree.root)
    assert tampered_leaf, "Tampered leaf data should fail verification!"
    print("[PASS] Tampered leaf data correctly rejected.")

    import copy

    tampered_proof = copy.deepcopy(proof)
    tampered_proof[0]["hash"] = b"\x00" * 32
    tampered_hash = not verify_proof(b"carol", tampered_proof, tree.root)
    assert tampered_hash, "Tampered proof hash should fail verification!"
    print("[PASS] Tampered proof hash correctly rejected.")

    items_odd = [b"alpha", b"beta", b"gamma"]
    tree_odd = MerkleTree(items_odd)
    proof_odd = tree_odd.get_proof(2)
    assert verify_proof(
        b"gamma", proof_odd, tree_odd.root
    ), "Proof for odd tree failed!"
    print(f"\n[Test 2] Odd leaf tree root: {tree_odd.root.hex()}")
    print("[PASS] Odd leaf count (3 leaves) handled correctly.")

    tree_single = MerkleTree([b"only"])
    proof_single = tree_single.get_proof(0)
    assert verify_proof(
        b"only", proof_single, tree_single.root
    ), "Single leaf proof failed!"
    print(f"\n[Test 3] Single leaf tree root: {tree_single.root.hex()}")
    print("[PASS] Single leaf tree works correctly.")

    for i, item in enumerate(items):
        proof_i = tree.get_proof(i)
        assert verify_proof(
            item, proof_i, tree.root
        ), f"Proof for index {i} failed!"
    print("\n[Test 4] All 4 proofs verified for 4-leaf tree.")
    print("[PASS] All leaf proofs valid.")

    proof_0 = tree.get_proof(0)
    assert not verify_proof(
        b"bob", proof_0, tree.root
    ), "Cross-index should fail!"
    print("\n[Test 5] Cross-index verification correctly fails.")
    print("[PASS] Wrong leaf with wrong proof rejected.")

    print("\n" + "=" * 60)
    print("ALL PART 1 TESTS PASSED ✓")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()
