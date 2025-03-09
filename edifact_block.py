import hashlib
import time
import json
from typing import List, Dict
import logging
from ecdsa import SigningKey, SECP256k1

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# EDIFACT Transaction class
class EDIFACTTransaction:
    def __init__(self, sender: str, receiver: str, message: str, signature: str = None):
        self.sender = sender  # Public key in hex
        self.receiver = receiver
        self.message = message  # Raw EDIFACT message
        self.signature = signature

    def to_dict(self) -> Dict:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "message": self.message,
        }

    def sign(self, private_key: SigningKey):
        transaction_data = json.dumps(self.to_dict(), sort_keys=True).encode()
        self.signature = private_key.sign(transaction_data).hex()

    def is_valid(self) -> bool:
        try:
            transaction_data = json.dumps(self.to_dict(), sort_keys=True).encode()
            verifying_key = SigningKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1).verifying_key
            return verifying_key.verify(bytes.fromhex(self.signature), transaction_data)
        except:
            return False

# Block class
class Block:
    def __init__(self, index: int, previous_hash: str, transactions: List[EDIFACTTransaction], timestamp: float):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "timestamp": self.timestamp,
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def is_valid(self) -> bool:
        for tx in self.transactions:
            if not tx.is_valid():
                return False
        return self.hash == self.calculate_hash()

# Blockchain class
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.nodes = set()

    def create_genesis_block(self) -> Block:
        genesis_transaction = EDIFACTTransaction("Genesis", "Network", "GENESIS MESSAGE")
        return Block(0, "0", [genesis_transaction], time.time())

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, block: Block):
        if block.is_valid() and block.previous_hash == self.get_latest_block().hash:
            self.chain.append(block)
            logging.info(f"Block {block.index} added to the blockchain.")
        else:
            logging.warning("Invalid block. Not added to the blockchain.")

    def add_transaction(self, transaction: EDIFACTTransaction):
        if transaction.is_valid():
            self.pending_transactions.append(transaction)
            logging.info(f"Transaction added: {transaction.to_dict()}")
        else:
            logging.warning("Invalid transaction. Not added to pending transactions.")

    def mine_pending_transactions(self):
        block = Block(
            index=len(self.chain),
            previous_hash=self.get_latest_block().hash,
            transactions=self.pending_transactions,
            timestamp=time.time(),
        )
        self.add_block(block)
        self.pending_transactions = []

    def is_chain_valid(self) -> bool:
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

# Wallet class for signing messages
class Wallet:
    def __init__(self):
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.verifying_key.to_string().hex()

    def send_message(self, receiver: str, message: str, blockchain: Blockchain):
        transaction = EDIFACTTransaction(self.public_key, receiver, message)
        transaction.sign(self.private_key)
        blockchain.add_transaction(transaction)

# Example usage
if __name__ == "__main__":
    blockchain = Blockchain()
    wallet1 = Wallet()
    wallet2 = Wallet()

    # Simulate sending EDIFACT messages
    wallet1.send_message(wallet2.public_key, "ORDERS+12345678+BUYER+SUPPLIER+20250309", blockchain)
    wallet2.send_message(wallet1.public_key, "INVOIC+98765432+SUPPLIER+BUYER+20250310", blockchain)

    # Mine pending messages
    blockchain.mine_pending_transactions()

    # Check blockchain validity
    logging.info(f"Is blockchain valid? {blockchain.is_chain_valid()}")

    # Print the blockchain
    for block in blockchain.chain:
        logging.info(f"Block {block.index}: {block.__dict__}")

