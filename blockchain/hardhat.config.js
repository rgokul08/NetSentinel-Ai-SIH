require('@nomicfoundation/hardhat-toolbox')
require('dotenv').config()

/**
 * Hardhat configuration for the CyberForecast AI integrity anchor.
 *
 * Networks
 *  - hardhat / localhost : local development (chainId 31337, the backend default)
 *  - amoy                  : Polygon Amoy testnet (chainId 80002) for the demo
 *
 * Secrets are read from `blockchain/.env` (never committed). Without a private
 * key the Amoy network is still declared so `hardhat compile` and `hardhat test`
 * work; deployment then fails fast with a clear message.
 */
const PRIVATE_KEY = process.env.BLOCKCHAIN_PRIVATE_KEY || process.env.PRIVATE_KEY || ''
const AMOY_RPC = process.env.BLOCKCHAIN_RPC_URL || process.env.AMOY_RPC_URL || 'https://rpc-amoy.polygon.technology'
const accounts = PRIVATE_KEY ? [PRIVATE_KEY.startsWith('0x') ? PRIVATE_KEY : `0x${PRIVATE_KEY}`] : []

module.exports = {
  solidity: {
    version: '0.8.24',
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts',
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    localhost: {
      url: process.env.LOCAL_RPC_URL || 'http://127.0.0.1:8545',
      chainId: 31337,
      // Use the configured key when deploying against a local Ganache/Hardhat
      // node; otherwise fall back to the built-in Hardhat accounts.
      ...(accounts.length ? { accounts } : {}),
    },
    amoy: {
      url: AMOY_RPC,
      chainId: 80002,
      accounts,
      gasPrice: 'auto',
    },
  },
  etherscan: {
    apiKey: {
      amoy: process.env.POLYGONSCAN_API_KEY || '',
    },
    customChains: [
      {
        network: 'amoy',
        chainId: 80002,
        urls: {
          apiURL: 'https://api-amoy.polygonscan.com/api',
          browserURL: 'https://amoy.polygonscan.com',
        },
      },
    ],
  },
  mocha: {
    timeout: 60000,
  },
}
