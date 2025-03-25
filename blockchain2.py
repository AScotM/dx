import hashlib
import time
import json
from uuid import uuid4
from typing import List, Dict
import logging
from ecdsa import SigningKey, SECP256k1
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Transaction class
class Transaction:
    """
    Class representing a blockchain transaction.
    """
    def __init__(self, sender: str, receiver: str, amount: float, signature: str = None):
        """
        Initialize a new transaction.
        """
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = signature

    def to_dict(self) -> Dict:
        """
        Convert the transaction data to a dictionary.
        """
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
        }

    def sign(self, private_key: SigningKey):
        """
        Sign the transaction with a private key.
        """
        transaction_data = json.dumps(self.to_dict(), sort_keys=True).encode()
        self.signature = private_key.sign(transaction_data).hex()

    def is_valid(self) -> bool:
        """
        Validate the transaction.
        """
        if self.sender == "Genesis":
            return True  # Genesis transactions are always valid
        try:
            transaction_data = json.dumps(self.to_dict(), sort_keys=True).encode()
            verifying_key = SigningKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1).verifying_key
            return verifying_key.verify(bytes.fromhex(self.signature), transaction_data)
        except Exception as e:
            logging.error(f"Transaction validation failed: {e}")
            return False

# Block class
class Block:
    """
    Class representing a block in the blockchain.
    """
    def __init__(self, index: int, previous_hash: str, transactions: List[Transaction], timestamp: float, nonce: int = 0):
        """
        Initialize a new block.
        """
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Calculate the hash of the block.
        """
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def mine_block(self, difficulty: int):
        """
        Mine the block by adjusting the nonce until it meets the difficulty target.
        """
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        logging.info(f"Block mined: {self.hash}")

    def is_valid(self) -> bool:
        """
        Validate the block and its transactions.
        """
        for tx in self.transactions:
            if not tx.is_valid():
                return False
        return self.hash == self.calculate_hash()

# Blockchain class
class Blockchain:
    """
    Class representing the blockchain.
    """
    def __init__(self, difficulty: int = 4):
        """
        Initialize the blockchain with a genesis block and a given difficulty.
        """
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions = []
        self.nodes = set()

    def create_genesis_block(self) -> Block:
        """
        Create the genesis block.
        """
        genesis_transaction = Transaction("Genesis", "Genesis Wallet", 1000)
        return Block(0, "0", [genesis_transaction], time.time())

    def get_latest_block(self) -> Block:
        """
        Get the latest block in the blockchain.
        """
        return self.chain[-1]

    def add_block(self, block: Block):
        """
        Add a block to the blockchain if it is valid.
        """
        if block.is_valid() and block.previous_hash == self.get_latest_block().hash:
            self.chain.append(block)
            logging.info(f"Block {block.index} added to the blockchain.")
        else:
            logging.warning("Invalid block. Not added to the blockchain.")

    def add_transaction(self, transaction: Transaction):
        """
        Add a transaction to the list of pending transactions if it is valid.
        """
        if transaction.is_valid():
            self.pending_transactions.append(transaction)
            logging.info(f"Transaction added: {transaction.to_dict()}")
        else:
            logging.warning("Invalid transaction. Not added to pending transactions.")

    def mine_pending_transactions(self, miner_address: str):
        """
        Mine the pending transactions and reward the miner.
        """
        block = Block(
            index=len(self.chain),
            previous_hash=self.get_latest_block().hash,
            transactions=self.pending_transactions,
            timestamp=time.time(),
        )
        block.mine_block(self.difficulty)
        self.add_block(block)
        self.pending_transactions = [Transaction("Network", miner_address, 10)]  # Mining reward
        logging.info(f"Mining reward sent to {miner_address}")

    def is_chain_valid(self) -> bool:
        """
        Check if the blockchain is valid.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if not current_block.is_valid():
                logging.warning(f"Block {current_block.index} is invalid.")
                return False

            if current_block.previous_hash != previous_block.hash:
                logging.warning(f"Block {current_block.index} has an invalid previous hash.")
                return False

        return True

    def register_node(self, node_address: str):
        """
        Register a new node with the blockchain.
        """
        self.nodes.add(node_address)
        logging.info(f"Node {node_address} registered.")

    def resolve_conflicts(self) -> bool:
        """
        Resolve conflicts by replacing the chain with the longest one in the network.
        """
        longest_chain = None
        max_length = len(self.chain)

        for node in self.nodes:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    node_chain = response.json()['chain']
                    if len(node_chain) > max_length and self.is_chain_valid():
                        longest_chain = node_chain
                        max_length = len(node_chain)
            except Exception as e:
                logging.error(f"Failed to fetch chain from node {node}: {e}")

        if longest_chain:
            self.chain = longest_chain
            logging.info("Chain replaced with a longer valid chain.")
            return True

        return False

# Wallet class
class Wallet:
    """
    Class representing a wallet.
    """
    def __init__(self):
        """
        Initialize a new wallet with a private and public key.
        """
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.verifying_key.to_string().hex()

    def send_money(self, receiver: str, amount: float, blockchain: Blockchain):
        """
        Send money to another wallet by creating and signing a transaction.
        """
        transaction = Transaction(self.public_key, receiver, amount)
        transaction.sign(self.private_key)
        blockchain.add_transaction(transaction)

# Example usage
if __name__ == "__main__":
    blockchain = Blockchain(difficulty=4)
    wallet1 = Wallet()
    wallet2 = Wallet()

    # Simulate transactions
    wallet1.send_money(wallet2.public_key, 100, blockchain)
    wallet2.send_money(wallet1.public_key, 50, blockchain)

    # Mine pending transactions
    blockchain.mine_pending_transactions(miner_address=wallet1.public_key)

    # Check blockchain validity
    logging.info(f"Is blockchain valid? {blockchain.is_chain_valid()}")

    # Print the blockchain
    for block in blockchain.chain:
        logging.info(f"Block {block.index}: {block.__dict__}")
