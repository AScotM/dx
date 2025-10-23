import hashlib
import time
import json
import random
import logging
import asyncio
import statistics
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter, deque
from ecdsa import SigningKey, SECP256k1, VerifyingKey
import textwrap
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# EDIFACT Message Templates with realistic business data
EDIFACT_TEMPLATES = {
    "ORDERS": {
        "template": "ORDERS+{order_id}+{buyer}+{supplier}+{date}+{product}+{quantity}+{price}",
        "chaos_factors": ["order_id", "quantity", "price"]
    },
    "INVOIC": {
        "template": "INVOIC+{invoice_id}+{supplier}+{buyer}+{date}+{amount}+{tax}+{due_date}",
        "chaos_factors": ["invoice_id", "amount", "tax"]
    },
    "DESADV": {
        "template": "DESADV+{despatch_id}+{supplier}+{buyer}+{date}+{items}+{carrier}",
        "chaos_factors": ["despatch_id", "items"]
    },
    "RECADV": {
        "template": "RECADV+{receipt_id}+{buyer}+{supplier}+{date}+{received_items}+{condition}",
        "chaos_factors": ["receipt_id", "received_items"]
    },
    "PAYORD": {
        "template": "PAYORD+{payment_id}+{payer}+{payee}+{date}+{amount}+{method}+{reference}",
        "chaos_factors": ["payment_id", "amount"]
    }
}

# Business entity database
BUSINESS_ENTITIES = {
    "buyers": ["ACME_CORP", "GLOBAL_TRADE", "MEGA_BUYERS", "QUALITY_IMPORTS", "BEST_BUYERS"],
    "suppliers": ["WORLD_SUPPLY", "PRIME_MFG", "ELITE_GOODS", "QUALITY_EXPORTS", "TOP_SUPPLIERS"],
    "products": ["ELECTRONICS", "RAW_MATERIALS", "FINISHED_GOODS", "COMPONENTS", "CONSUMABLES"],
    "carriers": ["FAST_SHIP", "RELIABLE_LOGISTICS", "GLOBAL_TRANSPORT", "QUICK_DELIVERY"]
}

class ChaoticEDIFACTGenerator:
    """Generates realistic but chaotic EDIFACT messages"""
    
    def __init__(self, volatility: float = 0.7, trend_strength: float = 0.3):
        self.volatility = volatility
        self.trend_strength = trend_strength
        self.message_counter = 0
        self.price_trends = {}
        self.order_patterns = {}
        
    def generate_message(self, message_type: str, sender: str, receiver: str) -> Tuple[str, float]:
        """Generate a chaotic EDIFACT message with calculated fee"""
        try:
            template = EDIFACT_TEMPLATES[message_type]
            params = self._generate_parameters(message_type, sender, receiver)
            
            message = template["template"].format(**params)
            fee = self._calculate_fee(message_type, params)
            
            self.message_counter += 1
            return message, fee
            
        except Exception as e:
            logging.error(f"Failed to generate {message_type} message: {e}")
            return f"{message_type}+ERROR+{sender}+{receiver}", 1.0
    
    def _generate_parameters(self, message_type: str, sender: str, receiver: str) -> Dict[str, Any]:
        """Generate parameters for EDIFACT messages with chaotic elements"""
        base_params = {
            "order_id": f"ORD{random.randint(100000, 999999)}",
            "invoice_id": f"INV{random.randint(100000, 999999)}",
            "despatch_id": f"DES{random.randint(100000, 999999)}",
            "receipt_id": f"REC{random.randint(100000, 999999)}",
            "payment_id": f"PAY{random.randint(100000, 999999)}",
            "buyer": random.choice(BUSINESS_ENTITIES["buyers"]),
            "supplier": random.choice(BUSINESS_ENTITIES["suppliers"]),
            "date": datetime.now().strftime("%Y%m%d"),
            "due_date": (datetime.now() + timedelta(days=30)).strftime("%Y%m%d"),
            "product": random.choice(BUSINESS_ENTITIES["products"]),
            "carrier": random.choice(BUSINESS_ENTITIES["carriers"]),
            "condition": random.choice(["GOOD", "DAMAGED", "PARTIAL"]),
            "items": str(random.randint(1, 50)),
            "received_items": str(random.randint(1, 50)),
            "quantity": str(random.randint(1, 1000))
        }
        
        # Add chaotic elements based on message type
        if message_type == "ORDERS":
            base_params.update(self._generate_order_parameters())
        elif message_type == "INVOIC":
            base_params.update(self._generate_invoice_parameters())
        elif message_type == "PAYORD":
            base_params.update(self._generate_payment_parameters())
            
        return base_params
    
    def _generate_order_parameters(self) -> Dict[str, Any]:
        """Generate order parameters with price trends and volatility"""
        product = random.choice(BUSINESS_ENTITIES["products"])
        
        # Establish price trends per product
        if product not in self.price_trends:
            self.price_trends[product] = {
                'base_price': random.uniform(10, 1000),
                'trend': random.choice([-1, 1]) * random.uniform(0.1, 0.5)
            }
        
        trend_data = self.price_trends[product]
        chaos_factor = random.uniform(-1, 1) * self.volatility
        price_variation = trend_data['trend'] + chaos_factor
        
        quantity = random.randint(1, 1000)
        base_price = trend_data['base_price'] * (1 + price_variation)
        price = max(1.0, base_price)  # Ensure positive price
        
        return {
            "quantity": str(quantity),
            "price": f"{price:.2f}",
            "product": product
        }
    
    def _generate_invoice_parameters(self) -> Dict[str, Any]:
        """Generate invoice parameters with realistic amounts and taxes"""
        amount = random.uniform(100, 10000)
        tax = amount * random.uniform(0.05, 0.25)  # 5-25% tax
        return {
            "amount": f"{amount:.2f}",
            "tax": f"{tax:.2f}"
        }
    
    def _generate_payment_parameters(self) -> Dict[str, Any]:
        """Generate payment parameters"""
        amount = random.uniform(50, 5000)
        method = random.choice(["BANK_TRANSFER", "CREDIT_CARD", "DIGITAL_WALLET"])
        return {
            "amount": f"{amount:.2f}",
            "method": method,
            "reference": f"REF{random.randint(10000, 99999)}"
        }
    
    def _calculate_fee(self, message_type: str, params: Dict[str, Any]) -> float:
        """Calculate transaction fee based on message complexity and value"""
        base_fees = {
            "ORDERS": 0.5,
            "INVOIC": 0.3,
            "DESADV": 0.2,
            "RECADV": 0.2,
            "PAYORD": 0.4
        }
        
        base_fee = base_fees.get(message_type, 0.1)
        
        # Add value-based fee for financial messages
        if message_type in ["INVOIC", "PAYORD"] and "amount" in params:
            try:
                amount = float(params["amount"])
                value_fee = amount * 0.001  # 0.1% of transaction value
                base_fee += min(value_fee, 10.0)  # Cap at 10 tokens
            except (ValueError, KeyError):
                pass
        
        # Add chaos to fee
        chaos_multiplier = 1 + (random.uniform(-1, 1) * self.volatility * 0.5)
        return max(0.1, base_fee * chaos_multiplier)

# Enhanced EDIFACT Transaction class with chaotic elements
class EDIFACTTransaction:
    def __init__(self, sender: str, receiver: str, message: str, fee: float = 0.0, signature: str = None):
        if not isinstance(fee, (int, float)) or fee < 0:
            raise ValueError("Fee must be a non-negative number")
        self.sender = sender
        self.receiver = receiver
        self.message = message
        self.fee = fee
        self.signature = signature
        self.timestamp = time.time()
        self.message_type = self._extract_message_type(message)

    def _extract_message_type(self, message: str) -> str:
        """Extract EDIFACT message type from message content"""
        if '+' in message:
            return message.split('+')[0]
        return "UNKNOWN"

    def to_dict(self) -> Dict:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "message": self.message,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "message_type": self.message_type
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

# Enhanced Block class with chaotic analysis - FIXED INITIALIZATION ORDER
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
        
        # Calculate chaos metrics BEFORE hash calculation
        self.chaos_metrics = self._calculate_chaos_metrics()
        
        # Now calculate hash with chaos metrics available
        self.hash = self.calculate_hash()

    def _calculate_chaos_metrics(self) -> Dict[str, Any]:
        """Calculate chaos metrics for the block"""
        try:
            if not self.transactions:
                return {
                    "message_type_distribution": {},
                    "total_fees": 0,
                    "fee_variance": 0,
                    "transaction_count": 0,
                    "chaos_score": 0
                }
                
            message_types = Counter(tx.message_type for tx in self.transactions)
            total_fees = sum(tx.fee for tx in self.transactions)
            
            # Calculate fee variance safely
            fees = [tx.fee for tx in self.transactions]
            if len(fees) > 1:
                fee_variance = statistics.variance(fees)
            else:
                fee_variance = 0
            
            chaos_score = min(1.0, fee_variance / max(1, total_fees)) if total_fees > 0 else 0
            
            return {
                "message_type_distribution": dict(message_types),
                "total_fees": total_fees,
                "fee_variance": fee_variance,
                "transaction_count": len(self.transactions),
                "chaos_score": chaos_score
            }
        except Exception as e:
            logging.warning(f"Chaos metrics calculation failed: {e}")
            return {
                "message_type_distribution": {},
                "total_fees": 0,
                "fee_variance": 0,
                "transaction_count": 0,
                "chaos_score": 0
            }

    def calculate_hash(self) -> str:
        try:
            block_data = {
                "index": self.index,
                "previous_hash": self.previous_hash,
                "transactions": [tx.to_dict() for tx in self.transactions],
                "timestamp": self.timestamp,
                "validator": self.validator,
                "chaos_metrics": self.chaos_metrics  # Now this exists!
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

# Chaotic Blockchain with enhanced analytics
class ChaoticBlockchain:
    def __init__(self, chaos_level: float = 0.5):
        try:
            self.chain = []
            self.pending_transactions = []
            self.balances = {}
            self.stakes = {}
            self.block_reward = 10.0
            self.chaos_level = chaos_level
            self.edifact_generator = ChaoticEDIFACTGenerator(volatility=chaos_level)
            self.transaction_analytics = {
                "message_types": Counter(),
                "total_volume": 0,
                "fee_analysis": [],
                "chaos_timeline": []
            }
            self.initialize_genesis_balances()
            self.chain = [self.create_genesis_block()]  # Create genesis AFTER initialization
        except Exception as e:
            logging.error(f"Blockchain initialization failed: {e}")
            raise

    def initialize_genesis_balances(self):
        try:
            self.balances["Genesis"] = 10000.0  # Higher initial balance for chaos
        except Exception as e:
            logging.error(f"Failed to initialize genesis balances: {e}")
            raise

    def create_genesis_block(self) -> Block:
        try:
            # Create a simple genesis transaction without requiring signatures
            genesis_transaction = EDIFACTTransaction("Genesis", "Network", "GENESIS_BLOCK", 0)
            
            # Create block without validator signature for genesis
            genesis_block = Block(0, "0", [genesis_transaction], time.time(), "Genesis")
            
            logging.info("Genesis block created successfully")
            return genesis_block
            
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
            self.update_analytics(block)
            
            logging.info(f"Block {block.index} added by validator {block.validator[:8]}...")
            logging.info(f"Chaos metrics: {block.chaos_metrics}")
            
        except Exception as e:
            logging.error(f"Failed to add block {block.index}: {e}")

    def update_analytics(self, block: Block):
        """Update transaction analytics with new block data"""
        try:
            for tx in block.transactions:
                self.transaction_analytics["message_types"][tx.message_type] += 1
                self.transaction_analytics["fee_analysis"].append(tx.fee)
                self.transaction_analytics["total_volume"] += tx.fee
            
            self.transaction_analytics["chaos_timeline"].append({
                "block_index": block.index,
                "timestamp": block.timestamp,
                "chaos_score": block.chaos_metrics.get("chaos_score", 0),
                "transaction_count": len(block.transactions)
            })
        except Exception as e:
            logging.warning(f"Analytics update failed: {e}")

    def update_balances(self, block: Block):
        try:
            # Skip balance updates for genesis block
            if block.index == 0:
                return
                
            # Reward validator with chaotic bonus based on block chaos
            chaos_bonus = block.chaos_metrics.get("chaos_score", 0) * self.block_reward
            total_reward = self.block_reward + chaos_bonus
            
            self.balances[block.validator] = self.balances.get(block.validator, 0) + total_reward
            
            # Process fees with chaotic adjustments
            for tx in block.transactions:
                if tx.sender != "Network" and tx.sender != "Genesis":
                    sender_balance = self.balances.get(tx.sender, 0)
                    if sender_balance < tx.fee:
                        # Chaotic forgiveness for low balances
                        if random.random() < self.chaos_level * 0.1:
                            logging.info(f"Chaotic fee forgiveness for {tx.sender[:8]}...")
                            continue
                        logging.warning(f"Insufficient balance for {tx.sender[:8]}... to pay fee {tx.fee}")
                        continue
                    
                    self.balances[tx.sender] = sender_balance - tx.fee
                    self.balances[block.validator] = self.balances.get(block.validator, 0) + tx.fee
                    
        except Exception as e:
            logging.error(f"Balance update for block {block.index} failed: {e}")

    def generate_chaotic_transactions(self, count: int, wallets: List['Wallet']):
        """Generate random EDIFACT transactions between wallets"""
        for _ in range(count):
            try:
                sender = random.choice(wallets)
                receiver = random.choice([w for w in wallets if w != sender])
                
                message_type = random.choice(list(EDIFACT_TEMPLATES.keys()))
                message, fee = self.edifact_generator.generate_message(
                    message_type, sender.public_key, receiver.public_key
                )
                
                # Chaotic fee adjustments
                if random.random() < self.chaos_level * 0.2:
                    fee *= random.uniform(0.5, 2.0)
                
                transaction = EDIFACTTransaction(sender.public_key, receiver.public_key, message, fee)
                transaction.sign(sender.private_key)
                self.add_transaction(transaction)
                
            except Exception as e:
                logging.warning(f"Failed to generate chaotic transaction: {e}")

    def add_transaction(self, transaction: EDIFACTTransaction):
        try:
            if not isinstance(transaction, EDIFACTTransaction):
                raise ValueError("Invalid transaction object")
            if not transaction.is_valid():
                logging.warning("Transaction signature invalid")
                return
            if self.balances.get(transaction.sender, 0) < transaction.fee:
                logging.warning(f"Insufficient balance for {transaction.sender[:8]}... to pay fee {transaction.fee}")
                return
                
            self.pending_transactions.append(transaction)
            logging.info(f"Transaction added: {transaction.message_type} from {transaction.sender[:8]}...")
            
        except Exception as e:
            logging.error(f"Failed to add transaction: {e}")

    def stake_tokens(self, address: str, amount: float):
        try:
            if not isinstance(amount, (int, float)) or amount <= 0:
                raise ValueError("Stake amount must be a positive number")
            current_balance = self.balances.get(address, 0)
            if current_balance < amount:
                logging.warning(f"Insufficient balance for {address[:8]}... to stake {amount}")
                return
            self.balances[address] = current_balance - amount
            self.stakes[address] = self.stakes.get(address, 0) + amount
            logging.info(f"{address[:8]}... staked {amount} tokens")
        except Exception as e:
            logging.error(f"Staking failed for {address}: {e}")

    def unstake_tokens(self, address: str, amount: float):
        try:
            if not isinstance(amount, (int, float)) or amount <= 0:
                raise ValueError("Unstake amount must be a positive number")
            current_stake = self.stakes.get(address, 0)
            if current_stake < amount:
                logging.warning(f"Insufficient stake for {address[:8]}... to unstake {amount}")
                return
            self.stakes[address] = current_stake - amount
            self.balances[address] = self.balances.get(address, 0) + amount
            logging.info(f"{address[:8]}... unstaked {amount} tokens")
        except Exception as e:
            logging.error(f"Unstaking failed for {address}: {e}")

    def select_validator(self) -> str:
        """Select validator with chaotic influence"""
        try:
            if not self.stakes:
                logging.warning("No staked tokens available for validator selection")
                return None
            
            total_stake = sum(self.stakes.values())
            if total_stake == 0:
                return None
            
            # Chaotic validator selection - occasionally pick random validator
            if random.random() < self.chaos_level * 0.1 and len(self.stakes) > 1:
                logging.info("Chaotic validator selection triggered!")
                return random.choice(list(self.stakes.keys()))
            
            # Normal weighted selection
            pick = random.uniform(0, total_stake)
            current = 0
            for address, stake in self.stakes.items():
                current += stake
                if current >= pick:
                    return address
                    
            return list(self.stakes.keys())[0]  # Fallback
            
        except Exception as e:
            logging.error(f"Validator selection failed: {e}")
            return None

    def create_block(self, validator_wallet: 'Wallet'):
        try:
            validator = validator_wallet.public_key
            if validator not in self.stakes or self.stakes[validator] == 0:
                logging.warning(f"{validator[:8]}... has no stake to create a block")
                return

            # Add block reward transaction
            reward_tx = EDIFACTTransaction("Network", validator, "Block Reward", self.block_reward)
            # Sign the reward transaction
            reward_tx.sign(validator_wallet.private_key)
            self.pending_transactions.append(reward_tx)

            block = Block(
                index=len(self.chain),
                previous_hash=self.get_latest_block().hash,
                transactions=self.pending_transactions.copy(),
                timestamp=time.time(),
                validator=validator
            )
            block.sign_block(validator_wallet.private_key)
            self.add_block(block)
            self.pending_transactions = []  # Clear only after successful block creation
            
        except Exception as e:
            logging.error(f"Block creation failed for {validator[:8]}...: {e}")

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

    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get comprehensive analytics summary"""
        try:
            total_blocks = len(self.chain)
            total_transactions = sum(len(block.transactions) for block in self.chain)
            
            chaos_scores = [cm.get("chaos_score", 0) for cm in self.transaction_analytics["chaos_timeline"]]
            avg_chaos = statistics.mean(chaos_scores) if chaos_scores else 0
            
            return {
                "chain_length": total_blocks,
                "total_transactions": total_transactions,
                "message_type_distribution": dict(self.transaction_analytics["message_types"]),
                "total_fee_volume": self.transaction_analytics["total_volume"],
                "average_chaos_score": avg_chaos,
                "active_validators": len(self.stakes),
                "total_staked": sum(self.stakes.values())
            }
        except Exception as e:
            logging.error(f"Analytics summary failed: {e}")
            return {"error": str(e)}

# Enhanced Wallet class
class Wallet:
    def __init__(self, name: str, initial_balance: float = 100.0):
        try:
            if not isinstance(initial_balance, (int, float)) or initial_balance < 0:
                raise ValueError("Initial balance must be a non-negative number")
            self.name = name
            self.private_key = SigningKey.generate(curve=SECP256k1)
            self.public_key = self.private_key.verifying_key.to_string().hex()
            self.initial_balance = initial_balance
            logging.info(f"Wallet {name} created with public key: {self.public_key[:16]}...")
        except Exception as e:
            logging.error(f"Wallet initialization failed: {e}")
            raise

    def send_edifact_message(self, receiver: str, message_type: str, blockchain: 'ChaoticBlockchain'):
        """Send an EDIFACT message using the chaotic generator"""
        try:
            message, fee = blockchain.edifact_generator.generate_message(
                message_type, self.public_key, receiver
            )
            transaction = EDIFACTTransaction(self.public_key, receiver, message, fee)
            transaction.sign(self.private_key)
            blockchain.add_transaction(transaction)
            logging.info(f"{self.name} sent {message_type} to {receiver[:8]}...")
        except Exception as e:
            logging.error(f"Failed to send EDIFACT message from {self.name}: {e}")

# Example usage with chaotic simulation
async def simulate_chaotic_edifact_network():
    """Simulate a chaotic EDIFACT blockchain network"""
    logging.info("Starting Chaotic EDIFACT Blockchain Simulation...")
    
    # Create blockchain with high chaos level
    blockchain = ChaoticBlockchain(chaos_level=0.7)
    
    # Create business entity wallets
    wallets = [
        Wallet("ACME_Corp", 1000.0),
        Wallet("Global_Trade", 1500.0),
        Wallet("Prime_Manufacturing", 1200.0),
        Wallet("Quality_Imports", 800.0),
        Wallet("Elite_Exports", 900.0)
    ]
    
    # Initialize balances and stakes
    for wallet in wallets:
        blockchain.balances[wallet.public_key] = wallet.initial_balance
        stake_amount = wallet.initial_balance * random.uniform(0.2, 0.6)
        blockchain.stake_tokens(wallet.public_key, stake_amount)
    
    # Simulation loop
    for round_num in range(5):  # Reduced rounds for testing
        logging.info(f"\n=== Simulation Round {round_num + 1} ===")
        
        # Generate chaotic transactions
        transaction_count = random.randint(3, 8)  # Reduced for testing
        blockchain.generate_chaotic_transactions(transaction_count, wallets)
        
        # Select validator and create block
        validator_address = blockchain.select_validator()
        if validator_address:
            validator_wallet = next((w for w in wallets if w.public_key == validator_address), None)
            if validator_wallet:
                blockchain.create_block(validator_wallet)
            else:
                logging.warning(f"No wallet found for validator {validator_address[:8]}...")
        else:
            logging.warning("No validator selected this round")
        
        # Some wallets send specific EDIFACT messages
        for _ in range(2):  # Reduced for testing
            sender = random.choice(wallets)
            receiver = random.choice([w for w in wallets if w != sender])
            message_type = random.choice(list(EDIFACT_TEMPLATES.keys()))
            sender.send_edifact_message(receiver.public_key, message_type, blockchain)
        
        # Wait between rounds
        await asyncio.sleep(0.5)  # Reduced wait time
    
    # Final analytics
    logging.info("\n=== Simulation Complete ===")
    analytics = blockchain.get_analytics_summary()
    logging.info(f"Final Analytics: {json.dumps(analytics, indent=2)}")
    logging.info(f"Blockchain Valid: {blockchain.is_chain_valid()}")
    
    # Print final state
    logging.info("\nFinal Balances:")
    for wallet in wallets:
        balance = blockchain.balances.get(wallet.public_key, 0)
        stake = blockchain.stakes.get(wallet.public_key, 0)
        logging.info(f"  {wallet.name}: Balance={balance:.2f}, Stake={stake:.2f}")

if __name__ == "__main__":
    try:
        # Run the chaotic simulation
        asyncio.run(simulate_chaotic_edifact_network())
        
    except Exception as e:
        logging.error(f"Simulation failed: {e}")
        import traceback
        traceback.print_exc()
