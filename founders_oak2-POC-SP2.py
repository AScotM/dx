import hashlib
import time
import json
import random
from typing import List, Dict
import logging
from ecdsa import SigningKey, SECP256k1, VerifyingKey

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# EDIFACT Transaction class (unchanged for simplicity)
class EDIFACTTransaction:
    def __init__(self, sender: str, receiver: str, message: str, fee: float = 0.0, signature: str = None):
        self.sender = sender
        self.receiver = receiver
        self.message = message
        self.fee = fee
        self.signature = signature

    def to_dict(self) -> Dict:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "message": self.message,
            "fee": self.fee,
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

# Block class (modified for PoS)
class Block:
    def __init__(self, index: int, previous_hash: str, transactions: List[EDIFACTTransaction], timestamp: float, validator: str, validator_signature: str = None):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.validator = validator  # Public key of the validator who created the block
        self.validator_signature = validator_signature
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "timestamp": self.timestamp,
            "validator": self.validator,
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def sign_block(self, private_key: SigningKey):
        self.validator_signature = private_key.sign(self.hash.encode()).hex()

    def is_valid(self) -> bool:
        for tx in self.transactions:
            if not tx.is_valid():
                return False
        try:
            verifying_key = VerifyingKey.from_string(bytes.fromhex(self.validator), curve=SECP256k1)
            return (self.hash == self.calculate_hash() and 
                    verifying_key.verify(bytes.fromhex(self.validator_signature), self.hash.encode()))
        except:
            return False

# Blockchain class (modified for PoS)
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.balances = {}  # Tracks token balances for each address
        self.stakes = {}   # Tracks staked tokens for each address
        self.block_reward = 10.0  # Reward for validators
        self.initialize_genesis_balances()

    def initialize_genesis_balances(self):
        # Give initial tokens to the network for demo purposes
        self.balances["Genesis"] = 1000.0

    def create_genesis_block(self) -> Block:
        genesis_transaction = EDIFACTTransaction("Genesis", "Network", "GENESIS MESSAGE")
        genesis_block = Block(0, "0", [genesis_transaction], time.time(), "Genesis")
        return genesis_block

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, block: Block):
        if block.is_valid() and block.previous_hash == self.get_latest_block().hash:
            self.chain.append(block)
            self.update_balances(block)
            logging.info(f"Block {block.index} added by validator {block.validator}")
        else:
            logging.warning("Invalid block. Not added to the blockchain.")

    def update_balances(self, block: Block):
        # Distribute block reward to the validator
        self.balances[block.validator] = self.balances.get(block.validator, 0) + self.block_reward
        # Process transaction fees
        for tx in block.transactions:
            self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.fee
            self.balances[block.validator] = self.balances.get(block.validator, 0) + tx.fee

    def add_transaction(self, transaction: EDIFACTTransaction):
        if transaction.is_valid() and self.balances.get(transaction.sender, 0) >= transaction.fee:
            self.pending_transactions.append(transaction)
            logging.info(f"Transaction added: {transaction.to_dict()}")
        else:
            logging.warning("Invalid transaction or insufficient balance.")

    def stake_tokens(self, address: str, amount: float):
        if self.balances.get(address, 0) >= amount:
            self.balances[address] -= amount
            self.stakes[address] = self.stakes.get(address, 0) + amount
            logging.info(f"{address} staked {amount} tokens.")
        else:
            logging.warning("Insufficient balance to stake.")

    def unstake_tokens(self, address: str, amount: float):
        if self.stakes.get(address, 0) >= amount:
            self.stakes[address] -= amount
            self.balances[address] = self.balances.get(address, 0) + amount
            logging.info(f"{address} unstaked {amount} tokens.")
        else:
            logging.warning("Insufficient staked amount.")

    def select_validator(self) -> str:
        # Weighted random selection based on stake
        total_stake = sum(self.stakes.values())
        if total_stake == 0:
            return None
        pick = random.uniform(0, total_stake)
        current = 0
        for address, stake in self.stakes.items():
            current += stake
            if current >= pick:
                return address
        return None

    def create_block(self, validator_wallet: 'Wallet'):
        validator = validator_wallet.public_key
        if validator not in self.stakes or self.stakes[validator] == 0:
            logging.warning(f"{validator} has no stake. Cannot create block.")
            return

        # Create a reward transaction for the validator
        reward_tx = EDIFACTTransaction("Network", validator, "Block Reward", self.block_reward)
        self.pending_transactions.append(reward_tx)

        # Create and sign the block
        block = Block(
            index=len(self.chain),
            previous_hash=self.get_latest_block().hash,
            transactions=self.pending_transactions,
            timestamp=time.time(),
            validator=validator
        )
        block.sign_block(validator_wallet.private_key)
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

# Wallet class (extended for staking)
class Wallet:
    def __init__(self, initial_balance: float = 100.0):
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.verifying_key.to_string().hex()
        self.initial_balance = initial_balance

    def send_message(self, receiver: str, message: str, fee: float, blockchain: Blockchain):
        transaction = EDIFACTTransaction(self.public_key, receiver, message, fee)
        transaction.sign(self.private_key)
        blockchain.add_transaction(transaction)

# Example usage
if __name__ == "__main__":
    # Create a blockchain
    blockchain = Blockchain()

    # Create wallets
    wallet1 = Wallet(100.0)
    wallet2 = Wallet(200.0)

    # Initialize balances for wallets
    blockchain.balances[wallet1.public_key] = wallet1.initial_balance
    blockchain.balances[wallet2.public_key] = wallet2.initial_balance

    # Stake tokens
    blockchain.stake_tokens(wallet1.public_key, 50.0)
    blockchain.stake_tokens(wallet2.public_key, 100.0)

    # Simulate sending EDIFACT messages
    wallet1.send_message(wallet2.public_key, "ORDERS+12345678+BUYER+SUPPLIER+20250309", 1.0, blockchain)
    wallet2.send_message(wallet1.public_key, "INVOIC+98765432+SUPPLIER+BUYER+20250310", 1.0, blockchain)

    # Validator creates a block (randomly selected based on stake)
    validator = blockchain.select_validator()
    if validator == wallet1.public_key:
        blockchain.create_block(wallet1)
    elif validator == wallet2.public_key:
        blockchain.create_block(wallet2)

    # Check blockchain validity
    logging.info(f"Is blockchain valid? {blockchain.is_chain_valid()}")

    # Print balances and stakes
    logging.info(f"Balances: {blockchain.balances}")
    logging.info(f"Stakes: {blockchain.stakes}")
