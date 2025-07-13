from typing import Any, Dict
from mcp.server.fastmcp import FastMCP
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_keys import keys
import os
from dotenv import load_dotenv
import logging
import uuid
import json

mcp  = FastMCP("crypto_wallet")
logging.basicConfig(level = logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
# Remove PROVIDER_URL variable and use direct Web3 connection
w3 = Web3(Web3.HTTPProvider('https://eth-mainnet.g.alchemy.com/v2/hGtMaKXmS_jfm9ZHNo2pSsx9tuNK1EIS'))
Account.enable_unaudited_hdwallet_features()
try:
    account = Account.from_key(os.getenv("PRIVATE_KEY"))
    wallet = {"account": account, "address": account.address, "private_key": os.getenv("PRIVATE_KEY")}
except Exception as e:
    raise ValueError(f"Failed to create account from private key: {str(e)}")

async def make_web3_request(func, *args, **kwargs) -> Any:
     """Execute a Web3.py function with error handling."""
     try:
         result = await func(*args, **kwargs) if func.__name__.startswith("async_") else func(*args, **kwargs)
         return result
     except Exception as e:
         logger.error(f"Web3 request failed: {str(e)}")
         raise ValueError(f"Web3 request failed: {str(e)}")
         return None
     
def format_wallet() -> str:
    """Format wallet information into a readable string."""
    return f"""
Address: {account.address}
"""

@mcp.tool()
async def wallet_create_random() -> str:
    """Create a new wallet with a random private key."""
    try:
        new_account = Account.create()
        return f"""New Wallet created: Address: {new_account.address} Private key: {new_account.key.hex()}
    (WARNING: Keep your private key safe and never share it with anyone!)"""
    except Exception as e:
        logger.error(f"Failed to create random wallet: {str(e)}")
        return f"Error creating wallet: {str(e)}"
    
    
@mcp.tool()
async def wallet_from_private_key(private_key: str) -> str:
    """Create a wallet from a private key (for reference, using provided key)."""
    try:
        if private_key != os.getenv("PRIVATE_KEY"):
            return "Error: Only the configured private key is supported"
        return format_wallet()
    except Exception as e:
        logger.error(f"Error loading wallet from private key: {str(e)}")
        return f"Error: {str(e)}"
    

@mcp.tool()
async def wallet_from_mnemonic(mnemonic: str) -> str:
    """Create a wallet from a mnemonic phrase."""
    try:
        new_account = Account.from_mnemonic(mnemonic)
        wallet["mnemonic"] = mnemonic
        return f"""
Wallet Created from Mnemonic:
Address: {new_account.address}
"""
    except Exception as e:
        logger.error(f"Error loading wallet from mnemonic: {str(e)}")
        return f"Error: {str(e)}"
    


@mcp.tool()
async def wallet_from_encrypted_json(json_wallet: str, password: str) -> str:
    """Create a wallet by decrypting an encrypted JSON wallet."""
    try:
        decrypted_key = Account.decrypt(json.loads(json_wallet), password)
        if decrypted_key.hex() != os.getenv("PRIVATE_KEY"):
            return "Error: Decrypted key does not match configured private key"
        return format_wallet()
    except Exception as e:
        logger.error(f"Error decrypting JSON wallet: {str(e)}")
        return f"Error: {str(e)}"
    

@mcp.tool()
async def wallet_encrypt(password: str) -> str:
    """Encrypt the wallet with a password."""
    try:
        encrypted = Account.encrypt(account.key, password)
        return f"""
Encrypted Wallet:
{json.dumps(encrypted, indent=2)}
"""
    except Exception as e:
        logger.error(f"Error encrypting wallet: {str(e)}")
        return f"Error: {str(e)}"

# Wallet Properties
@mcp.tool()
async def wallet_get_address() -> str:
    """Get the wallet address."""
    return format_wallet()

@mcp.tool()
async def wallet_get_public_key() -> str:
    """Get the wallet public key."""
    try:
        private_key = keys.PrivateKey(account.key)
        public_key = private_key.public_key
        return f"""
Public Key:
Address: {account.address}
Public Key: {public_key.to_hex()}
"""
    except Exception as e:
        logger.error(f"Error getting public key: {str(e)}")
        return f"Error: {str(e)}"

@mcp.tool()
async def wallet_get_private_key() -> str:
    """Get the wallet private key (with security warning)."""
    logger.warning("Retrieving private key - ensure secure handling")
    return f"""
Private Key (WARNING: Handle securely):
Address: {account.address}
Private Key: {account.key.hex()}
"""

@mcp.tool()
async def wallet_get_mnemonic() -> str:
    """Get the wallet mnemonic phrase (if available)."""
    if "mnemonic" not in wallet:
        return "Error: Mnemonic not available for this wallet"
    logger.warning("Retrieving mnemonic - ensure secure handling")
    return f"""
Mnemonic (WARNING: Handle securely):
Address: {account.address}
Mnemonic: {wallet["mnemonic"]}
"""

# Blockchain Methods
@mcp.tool()
async def wallet_get_balance() -> str:
    """Get the balance of the wallet."""
    balance = await make_web3_request(w3.eth.get_balance, account.address)
    if balance is None:
        return "Error: Failed to fetch balance"
    balance_eth = w3.from_wei(balance, "ether")
    return f"""
Balance:
Address: {account.address}
Balance: {balance_eth} ETH
"""

@mcp.tool()
async def wallet_get_chain_id() -> str:
    """Get the chain ID the wallet is connected to."""
    chain_id = await make_web3_request(lambda: w3.eth.chain_id)
    if chain_id is None:
        return "Error: Failed to fetch chain ID"
    return f"""
Chain ID:
{chain_id}
"""

@mcp.tool()
async def wallet_get_gas_price() -> str:
    """Get the current gas price."""
    gas_price = await make_web3_request(lambda: w3.eth.gas_price)
    if gas_price is None:
        return "Error: Failed to fetch gas price"
    return f"""
Gas Price:
{w3.from_wei(gas_price, "gwei")} Gwei
"""

@mcp.tool()
async def wallet_get_transaction_count() -> str:
    """Get the number of transactions sent from this account (nonce)."""
    nonce = await make_web3_request(w3.eth.get_transaction_count, account.address)
    if nonce is None:
        return "Error: Failed to fetch transaction count"
    return f"""
Transaction Count:
Address: {account.address}
Nonce: {nonce}
"""

@mcp.tool()
async def wallet_call(to_address: str, data: str) -> str:
    """Call a contract method without sending a transaction."""
    try:
        transaction = {
            "to": to_address,
            "data": data,
            "from": account.address
        }
        result = await make_web3_request(w3.eth.call, transaction)
        return f"""
    Contract call:
    To: {to_address}
    Data: {data}
    Result: {result.hex()}
    """
    except Exception as e:
        logger.error(f"Error calling contract: {str(e)}")
        return f"Error: {str(e)}"
    
# Transaction Methods
@mcp.tool()
async def wallet_send_transaction(to_address: str, value: float, gas_limit: int = 21000) -> str:
    """Send a transaction."""
    try:
        tx = {
            "to": w3.to_checksum_address(to_address),
            "value": w3.to_wei(value, "ether"),
            "gas": gas_limit,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": w3.eth.chain_id
        }
        signed_tx = w3.eth.account.sign_transaction(tx, account.key)
        tx_hash = await make_web3_request(w3.eth.send_raw_transaction, signed_tx.rawTransaction)
        if tx_hash is None:
            return "Error: Failed to send transaction"
        return f"""
Transaction Sent:
To: {to_address}
Value: {value} ETH
Tx Hash: {tx_hash.hex()}
"""
    except Exception as e:
        logger.error(f"Error sending transaction: {str(e)}")
        return f"Error: {str(e)}"
    
@mcp.tool()
async def wallet_sign_transaction(to_address: str, value: float, gas_limit: int = 21000) -> str:
    """Sign a transaction without sending it."""
    try:
        tx = {
            "to": w3.to_checksum_address(to_address),
            "value": w3.to_wei(value, "ether"),
            "gas": gas_limit,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": w3.eth.chain_id
        }
        signed_tx = w3.eth.account.sign_transaction(tx, account.key)
        return f"""
Signed Transaction:
To: {to_address}
Value: {value} ETH
Signed Tx: {signed_tx.rawTransaction.hex()}
"""
    except Exception as e:
        logger.error(f"Error signing transaction: {str(e)}")
        return f"Error: {str(e)}"
    
@mcp.tool()
async def wallet_populate_transaction(to_address: str, value: float, gas_limit: int = 21000) -> str:
    """Populate a transaction with missing fields."""
    try:
        tx = {
            "to": w3.to_checksum_address(to_address),
            "value": w3.to_wei(value, "ether"),
            "gas": gas_limit,
            "gasPrice": w3.eth.gas_price,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": w3.eth.chain_id
        }
        return f"""
Populated Transaction:
{json.dumps(tx, indent=2)}
"""
    except Exception as e:
        logger.error(f"Error populating transaction: {str(e)}")
        return f"Error: {str(e)}"
    
# Signing Methods
@mcp.tool()
async def wallet_sign_message(message: str) -> str:
    """Sign a message."""
    try:
        message_encoded = encode_defunct(text=message)
        signed_message = w3.eth.account.sign_message(message_encoded, private_key=account.key)
        return f"""
Signed Message:
Address: {account.address}
Signature: {signed_message.signature.hex()}
"""
    except Exception as e:
        logger.error(f"Error signing message: {str(e)}")
        return f"Error: {str(e)}"

@mcp.tool()
async def wallet_sign_typed_data(typed_data: Dict[str, Any]) -> str:
    """Sign typed data (EIP-712)."""
    try:
        message = encode_typed_data(primitive=typed_data)
        signed_message = w3.eth.account.sign_message(message, private_key=account.key)
        return f"""
Signed Typed Data:
Address: {account.address}
Signature: {signed_message.signature.hex()}
"""
    except Exception as e:
        logger.error(f"Error signing typed data: {str(e)}")
        return f"Error: {str(e)}"

@mcp.tool()
async def wallet_verify_message(message: str, signature: str) -> str:
    """Verify a signed message."""
    try:
        message_encoded = encode_defunct(text=message)
        address = w3.eth.account.recover_message(message_encoded, signature=signature)
        return f"""
Verified Message:
Recovered Address: {address}
"""
    except Exception as e:
        logger.error(f"Error verifying message: {str(e)}")
        return f"Error: {str(e)}"

@mcp.tool()
async def wallet_verify_typed_data(typed_data: Dict[str, Any], signature: str) -> str:
    """Verify signed typed data."""
    try:
        message = encode_typed_data(primitive=typed_data)
        address = w3.eth.account.recover_message(message, signature=signature)
        return f"""
Verified Typed Data:
Recovered Address: {address}
"""
    except Exception as e:
        logger.error(f"Error verifying typed data: {str(e)}")
        return f"Error: {str(e)}"

# Provider Methods
@mcp.tool()
async def provider_get_block(block_identifier: str = "latest") -> str:
    """Get a block by number or hash."""
    block = await make_web3_request(w3.eth.get_block, block_identifier)
    if block is None:
        return "Error: Failed to fetch block"
    return f"""
Block:
{json.dumps(dict(block), indent=2)}
"""

@mcp.tool()
async def provider_get_transaction(tx_hash: str) -> str:
    """Get a transaction by hash."""
    tx = await make_web3_request(w3.eth.get_transaction, tx_hash)
    if tx is None:
        return "Error: Failed to fetch transaction"
    return f"""
Transaction:
{json.dumps(dict(tx), indent=2)}
"""

@mcp.tool()
async def provider_get_transaction_receipt(tx_hash: str) -> str:
    """Get a transaction receipt."""
    receipt = await make_web3_request(w3.eth.get_transaction_receipt, tx_hash)
    if receipt is None:
        return "Error: Failed to fetch transaction receipt"
    return f"""
Transaction Receipt:
{json.dumps(dict(receipt), indent=2)}
"""

@mcp.tool()
async def provider_get_code(address: str) -> str:
    """Get the code at an address."""
    code = await make_web3_request(w3.eth.get_code, w3.to_checksum_address(address))
    if code is None:
        return "Error: Failed to fetch code"
    return f"""
Code:
Address: {address}
Code: {code.hex()}
"""

@mcp.tool()
async def provider_get_storage_at(address: str, position: int) -> str:
    """Get the storage at a position for an address."""
    storage = await make_web3_request(w3.eth.get_storage_at, w3.to_checksum_address(address), position)
    if storage is None:
        return "Error: Failed to fetch storage"
    return f"""
Storage:
Address: {address}
Position: {position}
Value: {storage.hex()}
"""

@mcp.tool()
async def provider_estimate_gas(to_address: str, value: float, data: str = "") -> str:
    """Estimate the gas required for a transaction."""
    tx = {
        "from": account.address,
        "to": w3.to_checksum_address(to_address),
        "value": w3.to_wei(value, "ether"),
        "data": data
    }
    gas = await make_web3_request(w3.eth.estimate_gas, tx)
    if gas is None:
        return "Error: Failed to estimate gas"
    return f"""
Estimated Gas:
To: {to_address}
Value: {value} ETH
Gas: {gas}
"""

@mcp.tool()
async def provider_get_logs(filter_params: Dict[str, Any]) -> str:
    """Get logs that match a filter."""
    logs = await make_web3_request(w3.eth.get_logs, filter_params)
    if logs is None:
        return "Error: Failed to fetch logs"
    return f"""
Logs:
{json.dumps(logs, indent=2)}
"""

@mcp.tool()
async def provider_get_ens_resolver(name: str) -> str:
    """Get the ENS resolver for a name."""
    resolver = await make_web3_request(w3.ens.resolver, name)
    if resolver is None:
        return "Error: Failed to fetch ENS resolver"
    return f"""
ENS Resolver:
Name: {name}
Resolver Address: {resolver.address}
"""

@mcp.tool()
async def provider_lookup_address(address: str) -> str:
    """Lookup the ENS name for an address."""
    name = await make_web3_request(w3.ens.name, w3.to_checksum_address(address))
    if name is None:
        return f"No ENS name found for address: {address}"
    return f"""
ENS Name:
Address: {address}
Name: {name}
"""

@mcp.tool()
async def provider_resolve_name(name: str) -> str:
    """Resolve an ENS name to an address."""
    address = await make_web3_request(w3.ens.address, name)
    if address is None:
        return f"No address found for ENS name: {name}"
    return f"""
ENS Address:
Name: {name}
Address: {address}
"""

# Network Methods
@mcp.tool()
async def network_get_network() -> str:
    """Get the current network information."""
    chain_id = await make_web3_request(lambda: w3.eth.chain_id)
    if chain_id is None:
        return "Error: Failed to fetch network info"
    return f"""
Network:
Chain ID: {chain_id}
"""

@mcp.tool()
async def network_get_block_number() -> str:
    """Get the current block number."""
    block_number = await make_web3_request(lambda: w3.eth.block_number)
    if block_number is None:
        return "Error: Failed to fetch block number"
    return f"""
Block Number:
{block_number}
"""
@mcp.tool()
async def network_get_fee_data() -> str:
    """Get the current fee data (base fee, max priority fee, etc.)."""
    try:
        fee_data = {
            "gas_price": w3.from_wei(w3.eth.gas_price, "gwei"),
            "max_fee_per_gas": w3.from_wei(w3.eth.max_fee_per_gas if hasattr(w3.eth, "max_fee_per_gas") else w3.eth.gas_price, "gwei"),
            "max_priority_fee_per_gas": w3.from_wei(w3.eth.max_priority_fee_per_gas if hasattr(w3.eth, "max_priority_fee_per_gas") else w3.eth.gas_price, "gwei")
        }
        return f"""
Fee Data:
{json.dumps(fee_data, indent=2)}
"""
    except Exception as e:
        logger.error(f"Error getting fee data: {str(e)}")
        return f"Error: {str(e)}"
    