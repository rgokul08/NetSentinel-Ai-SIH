/* eslint-disable no-console */
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { ethers } = require('ethers')

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') })

const ROOT = path.join(__dirname, '..')
const ARTIFACT = path.join(ROOT, 'artifacts', 'contracts', 'SecurityEventRegistry.sol', 'SecurityEventRegistry.json')

/**
 * Anchor security-event hashes on-chain from the command line.
 *
 * Mode 1 — single event (the eventId is SHA-256 of the ledger id, exactly like
 * backend/app/blockchain/hashing.py:event_id_to_bytes32):
 *
 *   npm run record -- --event-id 8f3c1d2e --event-hash 0x9a1b... --event-type alert
 *
 * Mode 2 — sync every ledger entry that the backend could not anchor (no RPC at
 * the time it was written). Requires a running backend and a JWT:
 *
 *   npm run record -- --sync --api-url http://localhost:8000/api --token <jwt> --limit 100
 *
 *   (or use --email/--password instead of --token to sign in with the demo admin)
 */

function parseArgs(argv) {
  const args = { limit: 100, apiUrl: 'http://localhost:8000/api' }
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i]
    if (!key.startsWith('--')) continue
    const name = key.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) {
      args[name] = true
    } else {
      args[name] = next
      i += 1
    }
  }
  return args
}

function resolveAddress(cliAddress) {
  if (cliAddress) return cliAddress
  if (process.env.BLOCKCHAIN_CONTRACT_ADDRESS) return process.env.BLOCKCHAIN_CONTRACT_ADDRESS
  const dir = path.join(__dirname, '..', 'deployments')
  if (fs.existsSync(dir)) {
    const files = fs.readdirSync(dir).filter((name) => name.endsWith('.json')).sort()
    for (const name of ['localhost.json', 'amoy.json', ...files]) {
      const file = path.join(dir, name)
      if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')).address
    }
  }
  throw new Error('No contract address. Pass --address, deploy first, or set BLOCKCHAIN_CONTRACT_ADDRESS.')
}

function eventIdToBytes32(eventId) {
  return `0x${crypto.createHash('sha256').update(String(eventId), 'utf8').digest('hex')}`
}

function normalizeHash(value) {
  const hex = String(value).toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`Invalid 32-byte hash: ${value}`)
  return `0x${hex}`
}

async function login(apiUrl, email, password) {
  const response = await fetch(`${apiUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!response.ok) throw new Error(`Login failed (${response.status}): ${await response.text()}`)
  const body = await response.json()
  if (!body.access_token) throw new Error('Login succeeded but no token was returned (MFA enabled? pass --token instead).')
  return body.access_token
}

async function fetchUnanchored(apiUrl, token, limit) {
  const response = await fetch(`${apiUrl}/blockchain/events?limit=${limit}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) throw new Error(`Ledger fetch failed (${response.status}): ${await response.text()}`)
  const body = await response.json()
  const items = body.items || []
  return items.filter((item) => !item.tx_hash && item.anchor_mode !== 'evm' && !item.is_tamper_demo)
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const rpcUrl = args.rpc || process.env.BLOCKCHAIN_RPC_URL || 'http://127.0.0.1:8545'
  const privateKey = args.key || process.env.BLOCKCHAIN_PRIVATE_KEY
  if (!privateKey) throw new Error('Set BLOCKCHAIN_PRIVATE_KEY in blockchain/.env (or pass --key) to anchor events.')

  const provider = new ethers.JsonRpcProvider(rpcUrl)
  const signer = new ethers.Wallet(privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`, provider)
  const address = resolveAddress(args.address)
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'))
  const registry = new ethers.Contract(address, artifact.abi, signer)
  const net = await provider.getNetwork()

  console.log(`RPC       : ${rpcUrl} (chainId ${net.chainId})`)
  console.log(`Contract  : ${address}`)
  console.log(`Recorder  : ${signer.address}`)
  console.log(`Authorized: ${signer.address === (await registry.owner()) ? 'owner' : (await registry.recorders(signer.address)) ? 'whitelisted' : 'NOT AUTHORIZED'}`)

  let batch = []

  if (args.sync) {
    const token = args.token || (args.email && args.password ? await login(args.apiUrl, args.email, args.password) : null)
    if (!token) throw new Error('--sync needs either --token <jwt> or --email/--password.')
    batch = (await fetchUnanchored(args.apiUrl, token, Number(args.limit))).map((item) => ({
      eventId: item.id,
      eventHash: item.event_hash,
      eventType: item.event_type || 'security_event',
    }))
    console.log(`\nFound ${batch.length} ledger entries without an on-chain anchor.`)
  } else if (args['event-id'] && args['event-hash']) {
    batch = [
      {
        eventId: args['event-id'],
        eventHash: args['event-hash'],
        eventType: args['event-type'] || 'manual_event',
      },
    ]
  } else {
    throw new Error('Provide --event-id/--event-hash, or --sync with --token (or --email/--password).')
  }

  if (!batch.length) {
    console.log('Nothing to anchor.')
    return
  }

  // Skip anything already anchored so the script is safely re-runnable.
  const pending = []
  for (const entry of batch) {
    const key = eventIdToBytes32(entry.eventId)
    const record = await registry.getEventRecord(key)
    if (record.exists) {
      console.log(`skip ${entry.eventId} (already anchored at ${record.timestamp})`)
      continue
    }
    pending.push({ ...entry, key })
  }

  if (!pending.length) {
    console.log('All requested events are already anchored.')
    return
  }

  if (pending.length === 1) {
    const entry = pending[0]
    const tx = await registry.recordEventHash(entry.key, normalizeHash(entry.eventHash), entry.eventType)
    const receipt = await tx.wait()
    console.log(`\nAnchored ${entry.eventId}`)
    console.log(`  hash  : ${normalizeHash(entry.eventHash)}`)
    console.log(`  type  : ${entry.eventType}`)
    console.log(`  tx    : ${tx.hash} (block ${receipt.blockNumber}, gas ${receipt.gasUsed})`)
    console.log(`  verify: ${await registry.verifyEventHash(entry.key, normalizeHash(entry.eventHash))}`)
    return
  }

  const tx = await registry.recordEventHashBatch(
    pending.map((entry) => entry.key),
    pending.map((entry) => normalizeHash(entry.eventHash)),
    pending.map((entry) => entry.eventType),
  )
  const receipt = await tx.wait()
  console.log(`\nAnchored ${pending.length} events in one transaction`)
  console.log(`  tx   : ${tx.hash} (block ${receipt.blockNumber}, gas ${receipt.gasUsed})`)
  console.log(`  total on-chain events: ${await registry.eventCount()}`)
}

main().catch((error) => {
  console.error(error.message || error)
  process.exitCode = 1
})
