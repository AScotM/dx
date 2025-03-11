import logging
import hashlib
import time

# Configure basic logging
logging.basicConfig(level=logging.INFO)

class Wallet:
    def __init__(self):
        # Simulate a public/private key pair (simplified for PoC)
        self.public_key = hashlib.sha256(str(time.time()).encode()).hexdigest()
        self.private_key = hashlib.sha256(str(self.public_key).encode()).hexdigest()

    def send_message(self, recipient_public_key, message, amount, blockchain):
        # Create a transaction with an EDIFACT-like message
        transaction = Transaction(
            sender_public_key=self.public_key,
            recipient_public_key=recipient_public_key,
            message=message,
            amount=amount
        )
        blockchain.add_transaction(transaction)
        return transaction

class Transaction:
    def __init__(self, sender_public_key, recipient_public_key, message, amount):
        self.sender_public_key = sender_public_key
        self.recipient_public_key = recipient_public_key
        self.message = message  # EDIFACT-like message
        self.amount = amount    # Could represent a token or cost
        self.timestamp = time.time()
        self.tx_hash = self.calculate_hash()

    def calculate_hash(self):
        # Simple hash of transaction details
        data = f"{self.sender_public_key}{self.recipient_public_key}{self.message}{self.amount}{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self):
        # Convert transaction to dictionary for logging
        return {
            "sender": self.sender_public_key[:8],  # Truncated for readability
            "recipient": self.recipient_public_key[:8],
            "message": self.message,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "tx_hash": self.tx_hash[:8]
        }

class Blockchain:
    def __init__(self):
        self.pending_transactions = []

    def add_transaction(self, transaction):
        # Add transaction to pending list
        self.pending_transactions.append(transaction)

# Main execution
if __name__ == "__main__":
    # Initialize blockchain
    blockchain = Blockchain()

    # Create wallets
    wallet1 = Wallet()
    wallet2 = Wallet()

    # Simulate sending EDIFACT messages
    wallet1.send_message(wallet2.public_key, "ORDERS+12345678+BUYER+SUPPLIER+20250309", 1.0, blockchain)
    wallet2.send_message(wallet1.public_key, "INVOIC+98765432+SUPPLIER+BUYER+20250310", 1.0, blockchain)

    # Print pending transactions
    logging.info("Pending Transactions:")
    for tx in blockchain.pending_transactions:
        logging.info(tx.to_dict())
