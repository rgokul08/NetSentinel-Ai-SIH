/* eslint-disable no-console */
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const ARTIFACT_PATH = path.join(__dirname, '..', 'artifacts', 'contracts', 'SecurityEventRegistry.sol', 'SecurityEventRegistry.json')
const { ethers } = require('ethers')

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') })

/**
 * Independent on-chain verification of the CyberForecast AI integrity ledger.
 *
 * For every ledger entry the backend exposes, this script recomputes the
 * contract key (SHA-256 of the ledger id) and asks the contract whether the
 * stored hash still matches. It proves that the off-chain database has not been
 * edited after anchoring — without trusting the backend's own verdict.
 *
 *   npm run verify:events -- --email admin@cyberforecast.ai --password Admin@1234
 *   npm run verify:events -- --token <jwt> --limit 500
 *   npm run verify:events -- --rpc https://rpc-amoy.polygon.technology --address 0xAbC... --token <jwt>
 *
 * Configuration precedence: CLI flag > blockchain/.env > default.
 *
 * Exit code 1 when any anchored entry mismatches (usable in CI).
 */

function parseArgs(argv) {
  const args = { limit: 200, apiUrl: 'http://localhost:8000/api' }
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i]
    if (!key.startsWith('--')) continue
    const name = key.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) args[name] = true
    else {
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

const eventIdToBytes32 = (id) => `0x${crypto.createHash('sha256').update(String(id), 'utf8').digest('hex')}`
const normalizeHash = (value) => `0x${String(value).toLowerCase().replace(/^0x/, '')}`

async function login(apiUrl, email, password) {
  const response = await fetch(`${apiUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!response.ok) throw new Error(`Login failed (${response.status}): ${await response.text()}`)
  const body = await response.json()
  if (!body.access_token) throw new Error('Login returned a challenge instead of a token (MFA?). Pass --token instead.')
  return body.access_token
}

async function fetchLedger(apiUrl, token, limit) {
  const response = await fetch(`${apiUrl}/blockchain/events?limit=${limit}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) throw new Error(`Ledger fetch failed (${response.status}): ${await response.text()}`)
  return response.json()
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const address = resolveAddress(args.address)
  const rpcUrl = args.rpc || process.env.BLOCKCHAIN_RPC_URL || 'http://127.0.0.1:8545'
  const provider = new ethers.JsonRpcProvider(rpcUrl)
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT_PATH, 'utf8'))
  const registry = new ethers.Contract(address, artifact.abi, provider)
  const net = await provider.getNetwork()
  const token = args.token || (args.email && args.password ? await login(args.apiUrl, args.email, args.password) : null)
  if (!token) throw new Error('Provide --token <jwt> or --email/--password for the backend API.')

  const ledger = await fetchLedger(args.apiUrl, token, Number(args.limit))
  const items = ledger.items || []

  console.log(`RPC          : ${rpcUrl} (chainId ${net.chainId})`)
  console.log(`Contract     : ${address}`)
  console.log(`On-chain     : ${await registry.eventCount()} anchored events`)
  console.log(`Ledger rows  : ${items.length} of ${ledger.pagination?.total ?? items.length} inspected`)
  console.log('')

  const summary = { matched: 0, mismatched: 0, notAnchored: 0, tamperDemo: 0 }
  const problems = []

  for (const item of items) {
    const key = eventIdToBytes32(item.id)
    const record = await registry.getEventRecord(key)

    if (item.is_tamper_demo) {
      summary.tamperDemo += 1
      if (record.exists) problems.push(`${item.id}: tamper-demo entry is anchored on-chain (it should not be)`)
      continue
    }
    if (!record.exists) {
      summary.notAnchored += 1
      continue
    }
    const expected = normalizeHash(item.event_hash)
    const actual = record.eventHash.toLowerCase()
    if (expected === actual) {
      summary.matched += 1
    } else {
      summary.mismatched += 1
      problems.push(`${item.id}: ledger hash ${expected} != on-chain ${actual}`)
    }
  }

  console.log(`  matched     : ${summary.matched}`)
  console.log(`  mismatched  : ${summary.mismatched}`)
  console.log(`  not anchored: ${summary.notAnchored}`)
  console.log(`  tamper demos: ${summary.tamperDemo} (intentionally excluded from anchoring)`)

  if (problems.length) {
    console.log('\nProblems:')
    problems.forEach((line) => console.log(`  - ${line}`))
  }

  if (summary.mismatched > 0) {
    console.log('\nRESULT: FAIL — the off-chain ledger no longer matches the chain.')
    process.exitCode = 1
    return
  }
  console.log(
    summary.matched > 0
      ? '\nRESULT: PASS — every anchored entry matches its on-chain commitment.'
      : '\nRESULT: NOTHING ANCHORED — no ledger entry is on this chain yet (the backend is running in local-hash-chain mode).',
  )
}

main().catch((error) => {
  console.error(error.message || error)
  process.exitCode = 1
})
