import hashlib
import time
import json
import random
from typing import List, Dict
import logging
from ecdsa import SigningKey, SECP256k1, VerifyingKey

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# EDIFACT Transaction class
class EDIFACTTransaction:
    def __init__(self, sender: str, receiver: str, message: str, fee: float = 0.0, signature: str = None):
        if not isinstance(fee, (int, float)) or fee < 0:
            raise ValueError("Fee must be a non-negative number")
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
        try:
            transaction_data = json.dumps(self.to_dict(), sort_keys=True).encode()
            self.signature = private_key.sign(transaction_data).hex()
        except Exception as e:
            logging.error(f"Failed to sign transaction: {e}")
            raise RuntimeError(f"Signature generation failed: {e}")

    def is_valid(self) -> bool:
        try:
            if not self.signature:
                return False
            transaction_data = json.dumps(self.to_dict(), sort_keys=True).encode()
            verifying_key = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
            return verifying_key.verify(bytes.fromhex(self.signature), transaction_data)
        except Exception as e:
            logging.warning(f"Transaction validation failed: {e}")
            return False

# Block class
class Block:
    def __init__(self, index: int, previous_hash: str, transactions: List[EDIFACTTransaction], 
                 timestamp: float, validator: str, validator_signature: str = None):
        if not isinstance(index, int) or index < 0:
            raise ValueError("Block index must be a non-negative integer")
        if not all(isinstance(tx, EDIFACTTransaction) for tx in transactions):
            raise ValueError("All transactions must be EDIFACTTransaction objects")
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.validator = validator
        self.validator_signature = validator_signature
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        try:
            block_data = {
                "index": self.index,
                "previous_hash": self.previous_hash,
                "transactions": [tx.to_dict() for tx in self.transactions],
                "timestamp": self.timestamp,
                "validator": self.validator,
            }
            return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()
        except Exception as e:
            logging.error(f"Failed to calculate block hash: {e}")
            raise RuntimeError(f"Hash calculation failed: {e}")

    def sign_block(self, private_key: SigningKey):
        try:
            self.validator_signature = private_key.sign(self.hash.encode()).hex()
        except Exception as e:
            logging.error(f"Failed to sign block: {e}")
            raise RuntimeError(f"Block signing failed: {e}")

    def is_valid(self) -> bool:
        try:
            for tx in self.transactions:
                if not tx.is_valid():
                    logging.warning(f"Invalid transaction in block {self.index}")
                    return False
            if self.hash != self.calculate_hash():
                logging.warning(f"Hash mismatch in block {self.index}")
                return False
            if not self.validator_signature:
                logging.warning(f"No validator signature in block {self.index}")
                return False
            verifying_key = VerifyingKey.from_string(bytes.fromhex(self.validator), curve=SECP256k1)
            return verifying_key.verify(bytes.fromhex(self.validator_signature), self.hash.encode())
        except Exception as e:
            logging.warning(f"Block {self.index} validation failed: {e}")
            return False

# Blockchain class
class Blockchain:
    def __init__(self):
        try:
            self.chain = [self.create_genesis_block()]
            self.pending_transactions = []
            self.balances = {}  # Tracks token balances
            self.stakes = {}    # Tracks staked tokens
            self.block_reward = 10.0
            self.initialize_genesis_balances()
        except Exception as e:
            logging.error(f"Blockchain initialization failed: {e}")
            raise

    def initialize_genesis_balances(self):
        try:
            self.balances["Genesis"] = 1000.0
        except Exception as e:
            logging.error(f"Failed to initialize genesis balances: {e}")
            raise

    def create_genesis_block(self) -> Block:
        try:
            genesis_transaction = EDIFACTTransaction("Genesis", "Network", "GENESIS MESSAGE")
            return Block(0, "0", [genesis_transaction], time.time(), "Genesis")
        except Exception as e:
            logging.error(f"Genesis block creation failed: {e}")
            raise

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, block: Block):
        try:
            if not isinstance(block, Block):
                raise ValueError("Invalid block object")
            if not block.is_valid():
                logging.warning(f"Block {block.index} is invalid")
                return
            if block.previous_hash != self.get_latest_block().hash:
                logging.warning(f"Block {block.index} has invalid previous hash")
                return
            self.chain.append(block)
            self.update_balances(block)
            logging.info(f"Block {block.index} added by validator {block.validator}")
        except Exception as e:
            logging.error(f"Failed to add block {block.index}: {e}")

    def update_balances(self, block: Block):
        try:
            # Reward validator
            self.balances[block.validator] = self.balances.get(block.validator, 0) + self.block_reward
            # Process fees
            for tx in block.transactions:
                if tx.sender != "Network":  # Skip reward transactions
                    sender_balance = self.balances.get(tx.sender, 0)
                    if sender_balance < tx.fee:
                        raise ValueError(f"Insufficient balance for {tx.sender} to pay fee {tx.fee}")
                    self.balances[tx.sender] = sender_balance - tx.fee
                    self.balances[block.validator] = self.balances.get(block.validator, 0) + tx.fee
        except Exception as e:
            logging.error(f"Balance update for block {block.index} failed: {e}")
            raise

    def add_transaction(self, transaction: EDIFACTTransaction):
        try:
            if not isinstance(transaction, EDIFACTTransaction):
                raise ValueError("Invalid transaction object")
            if not transaction.is_valid():
                logging.warning("Transaction signature invalid")
                return
            if self.balances.get(transaction.sender, 0) < transaction.fee:
                logging.warning(f"Insufficient balance for {transaction.sender} to pay fee {transaction.fee}")
                return
            self.pending_transactions.append(transaction)
            logging.info(f"Transaction added: {transaction.to_dict()}")
        except Exception as e:
            logging.error(f"Failed to add transaction: {e}")

    def stake_tokens(self, address: str, amount: float):
        try:
            if not isinstance(amount, (int, float)) or amount <= 0:
                raise ValueError("Stake amount must be a positive number")
            current_balance = self.balances.get(address, 0)
            if current_balance < amount:
                logging.warning(f"Insufficient balance for {address} to stake {amount}")
                return
            self.balances[address] = current_balance - amount
            self.stakes[address] = self.stakes.get(address, 0) + amount
            logging.info(f"{address} staked {amount} tokens")
        except Exception as e:
            logging.error(f"Staking failed for {address}: {e}")

    def unstake_tokens(self, address: str, amount: float):
        try:
            if not isinstance(amount, (int, float)) or amount <= 0:
                raise ValueError("Unstake amount must be a positive number")
            current_stake = self.stakes.get(address, 0)
            if current_stake < amount:
                logging.warning(f"Insufficient stake for {address} to unstake {amount}")
                return
            self.stakes[address] = current_stake - amount
            self.balances[address] = self.balances.get(address, 0) + amount
            logging.info(f"{address} unstaked {amount} tokens")
        except Exception as e:
            logging.error(f"Unstaking failed for {address}: {e}")

    def select_validator(self) -> str:
        try:
            total_stake = sum(self.stakes.values())
            if total_stake == 0:
                logging.warning("No staked tokens available for validator selection")
                return None
            pick = random.uniform(0, total_stake)
            current = 0
            for address, stake in self.stakes.items():
                current += stake
                if current >= pick:
                    return address
            logging.warning("Validator selection failed unexpectedly")
            return None
        except Exception as e:
            logging.error(f"Validator selection failed: {e}")
            return None

    def create_block(self, validator_wallet: 'Wallet'):
        try:
            validator = validator_wallet.public_key
            if validator not in self.stakes or self.stakes[validator] == 0:
                logging.warning(f"{validator} has no stake to create a block")
                return

            reward_tx = EDIFACTTransaction("Network", validator, "Block Reward", self.block_reward)
            self.pending_transactions.append(reward_tx)

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
        except Exception as e:
            logging.error(f"Block creation failed for {validator}: {e}")

    def is_chain_valid(self) -> bool:
        try:
            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]
                if not current_block.is_valid():
                    logging.warning(f"Block {current_block.index} is invalid")
                    return False
                if current_block.previous_hash != previous_block.hash:
                    logging.warning(f"Block {current_block.index} has invalid previous hash")
                    return False
            return True
        except Exception as e:
            logging.error(f"Chain validation failed: {e}")
            return False

# Wallet class
class Wallet:
    def __init__(self, initial_balance: float = 100.0):
        try:
            if not isinstance(initial_balance, (int, float)) or initial_balance < 0:
                raise ValueError("Initial balance must be a non-negative number")
            self.private_key = SigningKey.generate(curve=SECP256k1)
            self.public_key = self.private_key.verifying_key.to_string().hex()
            self.initial_balance = initial_balance
        except Exception as e:
            logging.error(f"Wallet initialization failed: {e}")
            raise

    def send_message(self, receiver: str, message: str, fee: float, blockchain: Blockchain):
        try:
            transaction = EDIFACTTransaction(self.public_key, receiver, message, fee)
            transaction.sign(self.private_key)
            blockchain.add_transaction(transaction)
        except Exception as e:
            logging.error(f"Failed to send message from {self.public_key}: {e}")

# Example usage
if __name__ == "__main__":
    try:
        # Create a blockchain
        blockchain = Blockchain()

        # Create wallets
        wallet1 = Wallet(100.0)
        wallet2 = Wallet(200.0)

        # Initialize balances
        blockchain.balances[wallet1.public_key] = wallet1.initial_balance
        blockchain.balances[wallet2.public_key] = wallet2.initial_balance

        # Stake tokens
        blockchain.stake_tokens(wallet1.public_key, 50.0)
        blockchain.stake_tokens(wallet2.public_key, 100.0)

        # Simulate sending EDIFACT messages
        wallet1.send_message(wallet2.public_key, "ORDERS+12345678+BUYER+SUPPLIER+20250309", 1.0, blockchain)
        wallet2.send_message(wallet1.public_key, "INVOIC+98765432+SUPPLIER+BUYER+20250310", 1.0, blockchain)

        # Validator creates a block
        validator = blockchain.select_validator()
        if validator == wallet1.public_key:
            blockchain.create_block(wallet1)
        elif validator == wallet2.public_key:
            blockchain.create_block(wallet2)
        else:
            logging.warning("No valid validator selected")

        # Check blockchain validity
        logging.info(f"Is blockchain valid? {blockchain.is_chain_valid()}")

        # Print balances and stakes
        logging.info(f"Balances: {blockchain.balances}")
        logging.info(f"Stakes: {blockchain.stakes}")

        # Test error cases
        blockchain.stake_tokens(wallet1.public_key, 1000.0)  # Insufficient balance
        blockchain.add_transaction(EDIFACTTransaction("Invalid", "Test", "MSG", 5.0))  # No signature

    except Exception as e:
        logging.error(f"Main execution failed: {e}")
