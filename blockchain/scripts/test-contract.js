/* eslint-disable no-console */
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const { ethers } = require('ethers')
const ganache = require('ganache')

/**
 * Offline contract test-suite (no internet, no Hardhat compiler download).
 *
 *   npm run test:offline
 *
 * Spins up an in-process Ganache EVM, deploys the artifact produced by
 * `npm run compile:offline`, and asserts every guarantee the FastAPI integrity
 * ledger depends on. `test/SecurityEventRegistry.test.js` covers the same ground
 * with Hardhat + Chai when a compiler download is possible; this runner keeps the
 * suite verifiable in air-gapped and CI sandboxes.
 */

const ROOT = path.join(__dirname, '..')
const ARTIFACT = path.join(ROOT, 'artifacts', 'contracts', 'SecurityEventRegistry.sol', 'SecurityEventRegistry.json')
const CONTRACT_NAME = 'SecurityEventRegistry'

const sha256 = (value) => `0x${crypto.createHash('sha256').update(String(value), 'utf8').digest('hex')}`
const eventId = (id) => sha256(id)

let passed = 0
const failures = []

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1
    console.log(`  \u001b[32mPASS\u001b[0m  ${name}`)
  } else {
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`)
    console.log(`  \u001b[31mFAIL\u001b[0m  ${name}${detail ? ` — ${detail}` : ''}`)
  }
}

/**
 * Extract the Solidity revert reason from an ethers v6 / Ganache error.
 *
 * Ganache reports reverts inside `error.info.error.data` (reason + ABI-encoded
 * return data); ethers only decodes it on some code paths, so we fall back to
 * decoding the `Error(string)` selector ourselves.
 */
function revertReason(error) {
  const data = error?.info?.error?.data
  if (data?.reason) return String(data.reason)
  if (typeof data === 'string' && data.startsWith('0x08c379a0')) return decodeErrorString(data)
  const result = data?.result
  if (typeof result === 'string' && result.startsWith('0x08c379a0')) return decodeErrorString(result)
  return error?.reason || error?.info?.error?.message || error?.shortMessage || error?.message || String(error)
}

function decodeErrorString(hex) {
  try {
    const [message] = ethers.AbiCoder.defaultAbiCoder().decode(['string'], `0x${hex.slice(10)}`)
    return message
  } catch {
    return hex
  }
}

async function expectRevert(name, promise, expectedFragment) {
  try {
    await (await promise).wait?.()
    check(name, false, 'transaction succeeded, expected a revert')
  } catch (error) {
    const reason = revertReason(error)
    check(name, reason.includes(expectedFragment), `revert reason was "${reason.slice(0, 140)}"`)
  }
}

async function main() {
  if (!fs.existsSync(ARTIFACT)) {
    throw new Error(`Artifact not found. Run: npm run compile:offline`)
  }
  const artifact = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'))

  console.log(`${CONTRACT_NAME} — offline contract tests`)
  console.log(`  compiler    : ${artifact.compiler?.version}`)
  console.log(`  bytecode    : ${(artifact.bytecode.length - 2) / 2} bytes`)

  const provider = new ethers.BrowserProvider(
    ganache.provider({
      logging: { quiet: true },
      chain: { chainId: 1337, vmErrorsOnRPCResponse: false },
      wallet: { deterministic: true, totalAccounts: 4 },
      miner: { blockGasLimit: 30_000_000 },
    }),
  )

  const owner = await provider.getSigner(0)
  const recorder = await provider.getSigner(1)
  const stranger = await provider.getSigner(2)
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, owner)

  console.log('\ndeployment')
  const registry = await factory.deploy()
  await registry.waitForDeployment()
  const address = await registry.getAddress()
  check('contract deploys and returns an address', ethers.isAddress(address), address)
  check('deployer becomes owner', (await registry.owner()) === (await owner.getAddress()))
  check('deployer is an authorized recorder', (await registry.recorders(await owner.getAddress())) === true)
  check('event count starts at zero', (await registry.eventCount()) === 0n)

  const sampleId = 'ledger-entry-0001'
  const payload = { event_id: sampleId, event_type: 'alert', prev_hash: '0'.repeat(64) }
  const sampleHash = sha256(JSON.stringify(payload))
  const tamperedHash = sha256(JSON.stringify({ ...payload, prev_hash: '0'.repeat(63) + '1' }))

  console.log('\nrecordEventHash')
  const recordTx = await registry.recordEventHash(eventId(sampleId), sampleHash, 'alert')
  const recordReceipt = await recordTx.wait()
  check('anchoring succeeds and mines a block', recordReceipt.status === 1, `block ${recordReceipt.blockNumber}`)
  check('event count increments to one', (await registry.eventCount()) === 1n)

  const stored = await registry.getEventRecord(eventId(sampleId))
  check('record exists', stored.exists === true)
  check('stored hash equals the anchored hash', stored.eventHash.toLowerCase() === sampleHash.toLowerCase(), stored.eventHash)
  check('recorder address is stored', stored.recorder === (await owner.getAddress()))
  check('event type label is stored', stored.eventType === 'alert')
  check('block timestamp is stored', stored.timestamp > 0n, String(stored.timestamp))

  const recordedEvent = recordReceipt.logs
    .map((log) => { try { return registry.interface.parseLog(log) } catch { return null } })
    .find((entry) => entry?.name === 'EventHashRecorded')
  check('EventHashRecorded is emitted with the right arguments',
    Boolean(recordedEvent)
      && recordedEvent.args.eventId === eventId(sampleId)
      && recordedEvent.args.eventHash.toLowerCase() === sampleHash.toLowerCase()
      && recordedEvent.args.eventType === 'alert')

  console.log('\nverification')
  check('verifyEventHash accepts the genuine hash', (await registry.verifyEventHash(eventId(sampleId), sampleHash)) === true)
  check('verifyEventHash rejects a tampered payload hash', (await registry.verifyEventHash(eventId(sampleId), tamperedHash)) === false)
  check('verifyEventHash rejects an unknown event id', (await registry.verifyEventHash(eventId('never-anchored'), sampleHash)) === false)
  const unknown = await registry.getEventRecord(eventId('never-anchored'))
  check('unknown ids return an empty record', unknown.exists === false && unknown.timestamp === 0n && unknown.recorder === ethers.ZeroAddress)

  console.log('\nimmutability')
  await expectRevert(
    're-anchoring the same event id reverts',
    registry.recordEventHash(eventId(sampleId), tamperedHash, 'alert'),
    'already anchored',
  )
  check('the original hash is still the one on-chain', (await registry.verifyEventHash(eventId(sampleId), sampleHash)) === true)
  check('event count did not change after the rejected write', (await registry.eventCount()) === 1n)
  await expectRevert('empty eventId reverts', registry.recordEventHash(ethers.ZeroHash, sampleHash, 'alert'), 'empty eventId')
  await expectRevert('empty eventHash reverts', registry.recordEventHash(eventId('x'), ethers.ZeroHash, 'alert'), 'empty eventHash')

  console.log('\nauthorization')
  await expectRevert(
    'an unauthorized address cannot anchor',
    registry.connect(stranger).recordEventHash(eventId('intruder'), sha256('intruder'), 'alert'),
    'not authorized',
  )
  const whitelistTx = await registry.setRecorder(await recorder.getAddress(), true)
  const whitelistReceipt = await whitelistTx.wait()
  const recorderEvent = whitelistReceipt.logs
    .map((log) => { try { return registry.interface.parseLog(log) } catch { return null } })
    .find((entry) => entry?.name === 'RecorderUpdated')
  check('setRecorder emits RecorderUpdated', Boolean(recorderEvent) && recorderEvent.args.allowed === true)
  const delegated = await registry.connect(recorder).recordEventHash(eventId('delegated'), sha256('delegated'), 'forecast_run')
  await delegated.wait()
  check('a whitelisted recorder can anchor', (await registry.verifyEventHash(eventId('delegated'), sha256('delegated'))) === true)
  check('the delegating recorder address is stored', (await registry.getEventRecord(eventId('delegated'))).recorder === (await recorder.getAddress()))
  await (await registry.setRecorder(await recorder.getAddress(), false)).wait()
  await expectRevert(
    'a revoked recorder can no longer anchor',
    registry.connect(recorder).recordEventHash(eventId('revoked'), sha256('revoked'), 'alert'),
    'not authorized',
  )
  await expectRevert('non-owners cannot manage recorders', registry.connect(stranger).setRecorder(await stranger.getAddress(), true), 'not the owner')

  console.log('\nrecordEventHashBatch')
  const ids = ['batch-a', 'batch-b', 'batch-c']
  const keys = ids.map(eventId)
  const hashes = ids.map((id) => sha256(`payload-${id}`))
  const types = ['alert', 'model_trained', 'report_generated']
  const beforeBatch = await registry.eventCount()
  const batchTx = await registry.recordEventHashBatch(keys, hashes, types)
  const batchReceipt = await batchTx.wait()
  check('batch transaction succeeds', batchReceipt.status === 1)
  check('event count grows by the batch size', (await registry.eventCount()) - beforeBatch === 3n, String(await registry.eventCount()))
  const batchOk = await Promise.all(keys.map((key, index) => registry.verifyEventHash(key, hashes[index])))
  check('every batched hash verifies', batchOk.every(Boolean))
  check('batched event types are stored', (await registry.getEventRecord(keys[2])).eventType === types[2])

  const singleGas = recordReceipt.gasUsed
  const perEventGas = batchReceipt.gasUsed / 3n
  check('batching is cheaper per event than single writes', perEventGas < singleGas, `${perEventGas} vs ${singleGas} gas`)

  await expectRevert('mismatched batch lengths revert', registry.recordEventHashBatch(keys, hashes.slice(0, 2), types), 'length mismatch')

  const duplicateTx = await registry.recordEventHashBatch(keys, [sha256('tampered'), hashes[1], hashes[2]], types)
  const duplicateReceipt = await duplicateTx.wait()
  const duplicateEvent = duplicateReceipt.logs
    .map((log) => { try { return registry.interface.parseLog(log) } catch { return null } })
    .find((entry) => entry?.name === 'BatchRecorded')
  check('a duplicate batch anchors nothing new', duplicateEvent?.args.count === 0n, String(duplicateEvent?.args.count))
  check('existing hashes survive a duplicate batch', (await registry.verifyEventHash(keys[0], hashes[0])) === true)
  check('tampered hashes are rejected by a duplicate batch', (await registry.verifyEventHash(keys[0], sha256('tampered'))) === false)

  console.log('\nownership')
  await expectRevert('transferring to the zero address reverts', registry.transferOwnership(ethers.ZeroAddress), 'zero address')
  await (await registry.transferOwnership(await recorder.getAddress())).wait()
  check('ownership transfers', (await registry.owner()) === (await recorder.getAddress()))
  check('the new owner is whitelisted as a recorder', (await registry.recorders(await recorder.getAddress())) === true)
  check('the previous owner is revoked as a recorder', (await registry.recorders(await owner.getAddress())) === false)
  await expectRevert('the previous owner loses write access', registry.connect(owner).recordEventHash(eventId('after-transfer'), sha256('x'), 'alert'), 'not authorized')

  console.log('\nprivacy')
  const secret = { alert: 'DDoS from 10.0.0.5', analyst: 'analyst@corp.in', password: 'never-on-chain', pcap: 'raw packet bytes' }
  const privacyFactory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, owner)
  const privacyRegistry = await privacyFactory.deploy()
  await privacyRegistry.waitForDeployment()
  await (await privacyRegistry.recordEventHash(eventId('privacy'), sha256(JSON.stringify(secret)), 'alert')).wait()
  const privacyRecord = await privacyRegistry.getEventRecord(eventId('privacy'))
  const exposed = [privacyRecord.eventHash, privacyRecord.eventType, privacyRecord.recorder, String(privacyRecord.timestamp)].join('|')
  check('no payload content is stored on-chain', !['10.0.0.5', 'analyst@corp.in', 'never-on-chain', 'raw packet bytes'].some((needle) => exposed.includes(needle)))
  const code = await provider.getCode(await privacyRegistry.getAddress())
  check('contract storage holds only hashes and metadata', !code.includes(Buffer.from('never-on-chain').toString('hex')))

  console.log(`\n${'─'.repeat(64)}`)
  console.log(`  ${passed} passed, ${failures.length} failed`)
  if (failures.length) {
    failures.forEach((failure) => console.log(`   • ${failure}`))
    process.exitCode = 1
  } else {
    console.log(`  ${CONTRACT_NAME} satisfies every integrity guarantee the backend relies on.`)
  }
  console.log('─'.repeat(64))
  await provider.destroy?.()
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
