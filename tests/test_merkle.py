"""
Comprehensive unit tests for the Merkle Tree Ethereum Verifier.
Run with: pytest tests/test_merkle.py -v
"""

import sys
import os
import copy
import hashlib
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from part1_tree import MerkleTree, MerkleNode, sha256_pair, verify_proof


# ─── sha256_pair ────────────────────────────────────────────────────────────

class TestSha256Pair:
    def test_returns_32_bytes(self):
        result = sha256_pair(b"left", b"right")
        assert len(result) == 32

    def test_deterministic(self):
        a = sha256_pair(b"a", b"b")
        b_ = sha256_pair(b"a", b"b")
        assert a == b_

    def test_order_matters(self):
        ab = sha256_pair(b"a", b"b")
        ba = sha256_pair(b"b", b"a")
        assert ab != ba

    def test_known_value(self):
        expected = hashlib.sha256(b"ab").digest()
        assert sha256_pair(b"a", b"b") == expected


# ─── MerkleTree Construction ─────────────────────────────────────────────────

class TestMerkleTreeConstruction:
    def test_single_leaf(self):
        tree = MerkleTree([b"only"])
        assert tree.root == hashlib.sha256(b"only").digest()

    def test_two_leaves(self):
        tree = MerkleTree([b"a", b"b"])
        left = hashlib.sha256(b"a").digest()
        right = hashlib.sha256(b"b").digest()
        expected_root = sha256_pair(left, right)
        assert tree.root == expected_root

    def test_four_leaves(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        assert len(tree.root) == 32

    def test_odd_leaves_three(self):
        tree = MerkleTree([b"a", b"b", b"c"])
        assert tree.root is not None
        assert len(tree.root) == 32

    def test_odd_leaves_five(self):
        tree = MerkleTree([b"a", b"b", b"c", b"d", b"e"])
        assert len(tree.root) == 32

    def test_root_is_bytes(self):
        tree = MerkleTree([b"x"])
        assert isinstance(tree.root, bytes)

    def test_root_changes_with_data(self):
        tree1 = MerkleTree([b"a", b"b"])
        tree2 = MerkleTree([b"a", b"c"])
        assert tree1.root != tree2.root

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            MerkleTree([])

    def test_large_tree(self):
        leaves = [f"tx_{i}".encode() for i in range(100)]
        tree = MerkleTree(leaves)
        assert len(tree.root) == 32


# ─── Proof Generation ────────────────────────────────────────────────────────

class TestProofGeneration:
    def test_proof_returns_list(self):
        tree = MerkleTree([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(0)
        assert isinstance(proof, list)

    def test_proof_has_correct_structure(self):
        tree = MerkleTree([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(0)
        for step in proof:
            assert "hash" in step
            assert "position" in step
            assert step["position"] in ("left", "right")
            assert isinstance(step["hash"], bytes)
            assert len(step["hash"]) == 32

    def test_proof_depth_power_of_two(self):
        tree = MerkleTree([b"a", b"b", b"c", b"d"])  # 4 leaves → depth 2
        proof = tree.get_proof(0)
        assert len(proof) == 2

    def test_proof_depth_eight_leaves(self):
        leaves = [f"{i}".encode() for i in range(8)]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        assert len(proof) == 3  # log2(8) = 3

    def test_proof_index_out_of_range(self):
        tree = MerkleTree([b"a", b"b"])
        with pytest.raises(IndexError):
            tree.get_proof(5)

    def test_proof_negative_index(self):
        tree = MerkleTree([b"a", b"b"])
        with pytest.raises(IndexError):
            tree.get_proof(-1)

    def test_all_indices_generate_proofs(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        for i in range(len(items)):
            proof = tree.get_proof(i)
            assert len(proof) > 0


# ─── Proof Verification ──────────────────────────────────────────────────────

class TestProofVerification:
    def test_valid_proof_index_0(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof = tree.get_proof(0)
        assert verify_proof(b"alice", proof, tree.root) is True

    def test_valid_proof_index_1(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof = tree.get_proof(1)
        assert verify_proof(b"bob", proof, tree.root) is True

    def test_valid_proof_index_2(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof = tree.get_proof(2)
        assert verify_proof(b"carol", proof, tree.root) is True

    def test_valid_proof_index_3(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof = tree.get_proof(3)
        assert verify_proof(b"dave", proof, tree.root) is True

    def test_tampered_leaf_fails(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof = tree.get_proof(2)
        assert verify_proof(b"mallory", proof, tree.root) is False

    def test_tampered_proof_hash_fails(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof = tree.get_proof(2)
        tampered = copy.deepcopy(proof)
        tampered[0]["hash"] = b"\x00" * 32
        assert verify_proof(b"carol", tampered, tree.root) is False

    def test_wrong_root_fails(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof = tree.get_proof(0)
        wrong_root = b"\xff" * 32
        assert verify_proof(b"alice", proof, wrong_root) is False

    def test_cross_index_fails(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)
        proof_0 = tree.get_proof(0)
        # Using bob's data with alice's proof
        assert verify_proof(b"bob", proof_0, tree.root) is False

    def test_single_leaf_proof(self):
        tree = MerkleTree([b"only"])
        proof = tree.get_proof(0)
        assert verify_proof(b"only", proof, tree.root) is True

    def test_odd_tree_valid_proof(self):
        items = [b"alpha", b"beta", b"gamma"]
        tree = MerkleTree(items)
        for i, item in enumerate(items):
            proof = tree.get_proof(i)
            assert verify_proof(item, proof, tree.root) is True, f"Failed for index {i}"

    def test_verify_returns_bool(self):
        tree = MerkleTree([b"a", b"b"])
        proof = tree.get_proof(0)
        result = verify_proof(b"a", proof, tree.root)
        assert isinstance(result, bool)

    def test_large_tree_verification(self):
        leaves = [f"transaction_{i}".encode() for i in range(64)]
        tree = MerkleTree(leaves)
        for i in range(0, 64, 8):  # Check every 8th leaf
            proof = tree.get_proof(i)
            assert verify_proof(f"transaction_{i}".encode(), proof, tree.root) is True

    def test_tamper_any_proof_step_fails(self):
        items = [b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"]
        tree = MerkleTree(items)
        proof = tree.get_proof(0)
        for j in range(len(proof)):
            tampered = copy.deepcopy(proof)
            tampered[j]["hash"] = b"\xab" * 32
            assert verify_proof(b"a", tampered, tree.root) is False, \
                f"Tampering step {j} should have failed!"


# ─── Integration: Task Example ───────────────────────────────────────────────

class TestTaskExample:
    """Replicates the exact test cases from the task specification."""

    def test_task_spec_example(self):
        items = [b"alice", b"bob", b"carol", b"dave"]
        tree = MerkleTree(items)

        # Generate and verify a proof for "carol" (index 2)
        proof = tree.get_proof(2)
        assert verify_proof(b"carol", proof, tree.root)

        # Tamper with the data and confirm verification fails
        assert not verify_proof(b"mallory", proof, tree.root)

        # Tamper with a proof hash and confirm verification fails
        tampered_proof = copy.deepcopy(proof)
        tampered_proof[0]["hash"] = b"\x00" * 32
        assert not verify_proof(b"carol", tampered_proof, tree.root)


# ─── hash_transaction ────────────────────────────────────────────────────────

class TestHashTransaction:
    def test_simple_hash(self):
        from part3_verify import hash_transaction_simple
        tx = {"hash": "0xabc123"}
        result = hash_transaction_simple(tx)
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_consistent_hash(self):
        from part3_verify import hash_transaction_simple
        tx = {"hash": "0xdeadbeef"}
        assert hash_transaction_simple(tx) == hash_transaction_simple(tx)

    def test_different_hashes_differ(self):
        from part3_verify import hash_transaction_simple
        tx1 = {"hash": "0xaaa"}
        tx2 = {"hash": "0xbbb"}
        assert hash_transaction_simple(tx1) != hash_transaction_simple(tx2)


# ─── reconstruct_transactions_root ───────────────────────────────────────────

class TestReconstructRoot:
    def test_reconstruct_returns_bytes(self):
        from part3_verify import reconstruct_transactions_root
        txs = [{"hash": f"0x{i:064x}"} for i in range(4)]
        root = reconstruct_transactions_root(txs)
        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_reconstruct_deterministic(self):
        from part3_verify import reconstruct_transactions_root
        txs = [{"hash": "0x1"}, {"hash": "0x2"}, {"hash": "0x3"}]
        assert reconstruct_transactions_root(txs) == reconstruct_transactions_root(txs)

    def test_reconstruct_empty_raises(self):
        from part3_verify import reconstruct_transactions_root
        with pytest.raises(ValueError):
            reconstruct_transactions_root([])

    def test_reconstruct_changes_with_transactions(self):
        from part3_verify import reconstruct_transactions_root
        txs1 = [{"hash": "0x1"}, {"hash": "0x2"}]
        txs2 = [{"hash": "0x1"}, {"hash": "0x3"}]
        assert reconstruct_transactions_root(txs1) != reconstruct_transactions_root(txs2)
