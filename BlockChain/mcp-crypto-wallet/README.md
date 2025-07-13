# MCP Crypto Wallet

[![MCP](https://badge.mcpx.dev 'MCP')](https://github.com/yourusername/mcp-crypto-wallet)
[![MCP Server](https://badge.mcpx.dev?type=server&features=resources,tools 'MCP Server with Resources & Tools')](https://github.com/yourusername/mcp-crypto-wallet)
[![MCP Client](https://badge.mcpx.dev?type=client&features=prompts,tools 'MCP Client with Prompts & Tools')](https://github.com/yourusername/mcp-crypto-wallet)
[![MCP Dev](https://badge.mcpx.dev?type=dev 'MCP Dev')](https://github.com/yourusername/mcp-crypto-wallet)

A high-performance, secure, and extensible crypto wallet implementation built on the Model Context Protocol (MCP). This MCP server provides comprehensive blockchain interaction capabilities with built-in security features and AI-powered automation.

## 🚀 Features

### 🔐 Wallet Management
- Create wallets from various sources (random, private key, mnemonic, encrypted JSON)
- Secure wallet encryption and decryption
- Multi-account support with hierarchical deterministic (HD) wallet capabilities
- Hardware wallet integration support

### ⛓️ Blockchain Interaction
- Multi-chain support (Ethereum, EVM-compatible chains, and more)
- Real-time balance and transaction monitoring
- Gas estimation and optimization
- Contract interaction and deployment

### 🔒 Security Features
- Secure key management
- Transaction signing with hardware wallet support
- Message and typed data signing (EIP-712)
- Built-in security audits and vulnerability detection

### 🤖 AI-Powered Automation
- Smart contract interaction suggestions
- Gas price optimization
- Anomaly detection for transactions
- Automated security audits

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/0x-Professor/MCPServers.git
cd BlockChain
cd mcp-crypto-wallet

# Set up environment variables
uv venv

# Install dependencies
uv add -r requirements.txt
# or
uvx add -r requirements.txt

# Set up environment variables
cp .env.example .env
add your API KEY and Private key of Wallet 
# Edit .env with your configuration
ALCHEMY_API_KEY= "You can use any key "
PRIVATE_KEY=

# Start the MCP server
uv run mcp dev filename.py
```

## 📚 MCP TOOLS Reference

### Wallet Management

#### `wallet_create_random()`
Create a new wallet with a random private key.

#### `wallet_from_private_key(privateKey: string)`
Create a wallet from an existing private key.

#### `wallet_from_mnemonic(mnemonic: string, path?: string)`
Create a wallet from a mnemonic phrase with optional derivation path.

#### `wallet_from_encrypted_json(json: string, password: string)`
Create a wallet by decrypting an encrypted JSON wallet.

#### `wallet_encrypt(password: string, options?: object)`
Encrypt the wallet with a password.

### Wallet Properties

#### `wallet_get_address()`
Get the wallet address.

#### `wallet_get_public_key()`
Get the wallet public key.

#### `wallet_get_private_key()`
⚠️ Get the wallet private key (use with caution).

#### `wallet_get_mnemonic()`
Get the wallet mnemonic phrase (if available).

### Blockchain Methods

#### `wallet_get_balance(blockTag?: BlockTag)`
Get the balance of the wallet.

#### `wallet_get_chain_id()`
Get the chain ID the wallet is connected to.

#### `wallet_get_gas_price()`
Get the current gas price.

#### `wallet_get_transaction_count(blockTag?: BlockTag)`
Get the transaction count (nonce) of the wallet.

#### `wallet_call(transaction: Deferrable<TransactionRequest>, blockTag?: BlockTag)`
Call a contract method without sending a transaction.

### Transaction Methods

#### `wallet_send_transaction(transaction: Deferrable<TransactionRequest>)`
Send a transaction.

#### `wallet_sign_transaction(transaction: Deferrable<TransactionRequest>)`
Sign a transaction without sending it.

#### `wallet_populate_transaction(transaction: Deferrable<TransactionRequest>)`
Populate a transaction with missing fields.

### Signing Methods

#### `wallet_sign_message(message: string | Bytes)`
Sign a message.

#### `wallet_sign_typed_data(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>)`
Sign typed data (EIP-712).

#### `wallet_verify_message(message: string | Bytes, signature: SignatureLike)`
Verify a signed message.

### Provider Methods

#### `provider_get_block(blockHashOrBlockTag: BlockTag | string)`
Get a block by number or hash.

#### `provider_get_transaction(transactionHash: string)`
Get a transaction by hash.

#### `provider_get_transaction_receipt(transactionHash: string)`
Get a transaction receipt.

#### `provider_get_code(address: string, blockTag?: BlockTag)`
Get the code at an address.

## 🔗 Network Support

This MCP server supports multiple networks out of the box:

- Ethereum Mainnet
- Ethereum Testnets (Goerli, Sepolia)
- Polygon
- Binance Smart Chain
- Arbitrum
- Optimism
- And more...

## 🛡️ Security

- All sensitive operations are performed in a secure environment
- Private keys are never stored in plaintext
- Hardware wallet support for additional security
- Regular security audits and updates

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌐 Community

Join our community to get help and discuss MCP server development:

- [Discord](https://discord.gg/your-invite-link)Coming Soon 
- [Twitter](https://twitter.com/your-handle) Not Available 
- [GitHub Discussions](https://github.com/0x-Professor/mcp-crypto-wallet/discussions)

## 🙏 Acknowledgments

- Built with ❤️ using [web3.py]
- Inspired by the MCP protocol
- Our amazing community of contributors and users