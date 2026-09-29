const { expect } = require('chai')
const { ethers } = require('hardhat')
const crypto = require('crypto')

/**
 * Contract tests for the CyberForecast AI integrity anchor.
 *
 * These mirror the guarantees the FastAPI ledger relies on:
 *   - an anchored hash can be verified by anyone,
 *   - an anchored hash can never be overwritten (immutability),
 *   - only the owner or whitelisted recorders may write,
 *   - batches are gas-efficient and skip duplicates,
 *   - tampering with the off-chain payload changes the hash and fails verification.
 */

const sha256 = (value) => `0x${crypto.createHash('sha256').update(String(value), 'utf8').digest('hex')}`
const eventId = (id) => sha256(id)

describe('SecurityEventRegistry', () => {
  let registry
  let owner
  let recorder
  let stranger

  const sampleId = 'ledger-entry-0001'
  const sampleHash = sha256(JSON.stringify({ event_id: sampleId, event_type: 'alert', prev_hash: '0'.repeat(64) }))
  const tamperedHash = sha256(JSON.stringify({ event_id: sampleId, event_type: 'alert', prev_hash: '0'.repeat(63) + '1' }))

  beforeEach(async () => {
    ;[owner, recorder, stranger] = await ethers.getSigners()
    const factory = await ethers.getContractFactory('SecurityEventRegistry')
    registry = await factory.deploy()
    await registry.waitForDeployment()
  })

  describe('deployment', () => {
    it('sets the deployer as owner and authorized recorder', async () => {
      expect(await registry.owner()).to.equal(owner.address)
      expect(await registry.recorders(owner.address)).to.equal(true)
      expect(await registry.eventCount()).to.equal(0n)
    })
  })

  describe('recordEventHash', () => {
    it('anchors a hash and emits EventHashRecorded', async () => {
      const tx = registry.recordEventHash(eventId(sampleId), sampleHash, 'alert')
      await expect(tx).to.emit(registry, 'EventHashRecorded')

      const receipt = await (await tx).wait()
      const parsed = receipt.logs
        .map((log) => { try { return registry.interface.parseLog(log) } catch { return null } })
        .find((entry) => entry && entry.name === 'EventHashRecorded')

      expect(parsed.args.eventId).to.equal(eventId(sampleId))
      expect(parsed.args.eventHash).to.equal(sampleHash)
      expect(parsed.args.eventType).to.equal('alert')
      expect(parsed.args.recorder).to.equal(owner.address)
      expect(parsed.args.timestamp).to.be.greaterThan(0n)
      expect(await registry.eventCount()).to.equal(1n)
    })

    it('stores the block timestamp and recorder address', async () => {
      await registry.recordEventHash(eventId(sampleId), sampleHash, 'alert')
      const record = await registry.getEventRecord(eventId(sampleId))

      expect(record.exists).to.equal(true)
      expect(record.eventHash).to.equal(sampleHash)
      expect(record.recorder).to.equal(owner.address)
      expect(record.eventType).to.equal('alert')
      expect(record.timestamp).to.be.greaterThan(0n)
    })

    it('verifies the exact hash and rejects a tampered one', async () => {
      await registry.recordEventHash(eventId(sampleId), sampleHash, 'alert')

      expect(await registry.verifyEventHash(eventId(sampleId), sampleHash)).to.equal(true)
      // Editing the off-chain payload changes the recomputed hash -> verification fails.
      expect(await registry.verifyEventHash(eventId(sampleId), tamperedHash)).to.equal(false)
    })

    it('is immutable: the same event id cannot be re-anchored', async () => {
      await registry.recordEventHash(eventId(sampleId), sampleHash, 'alert')

      await expect(registry.recordEventHash(eventId(sampleId), tamperedHash, 'alert'))
        .to.be.revertedWith('SecurityEventRegistry: event already anchored (immutable)')

      expect(await registry.verifyEventHash(eventId(sampleId), tamperedHash)).to.equal(false)
      expect(await registry.eventCount()).to.equal(1n)
    })

    it('rejects empty identifiers and hashes', async () => {
      await expect(registry.recordEventHash(ethers.ZeroHash, sampleHash, 'alert'))
        .to.be.revertedWith('SecurityEventRegistry: empty eventId')
      await expect(registry.recordEventHash(eventId(sampleId), ethers.ZeroHash, 'alert'))
        .to.be.revertedWith('SecurityEventRegistry: empty eventHash')
    })

    it('rejects unauthorized recorders', async () => {
      await expect(registry.connect(stranger).recordEventHash(eventId(sampleId), sampleHash, 'alert'))
        .to.be.revertedWith('SecurityEventRegistry: caller is not authorized to record events')
    })

    it('accepts a whitelisted recorder and can revoke it again', async () => {
      await expect(registry.setRecorder(recorder.address, true))
        .to.emit(registry, 'RecorderUpdated')
        .withArgs(recorder.address, true)

      await expect(registry.connect(recorder).recordEventHash(eventId(sampleId), sampleHash, 'alert')).to.not.be.reverted
      const record = await registry.getEventRecord(eventId(sampleId))
      expect(record.recorder).to.equal(recorder.address)

      await registry.setRecorder(recorder.address, false)
      await expect(registry.connect(recorder).recordEventHash(eventId('next'), sha256('next'), 'alert'))
        .to.be.revertedWith('SecurityEventRegistry: caller is not authorized to record events')
    })

    it('only the owner can manage recorders', async () => {
      await expect(registry.connect(stranger).setRecorder(stranger.address, true))
        .to.be.revertedWith('SecurityEventRegistry: caller is not the owner')
    })
  })

  describe('recordEventHashBatch', () => {
    const ids = ['a', 'b', 'c']
    const keys = ids.map(eventId)
    const hashes = ids.map((id) => sha256(`payload-${id}`))
    const types = ['alert', 'forecast_run', 'model_activated']

    it('anchors every entry in one transaction', async () => {
      await expect(registry.recordEventHashBatch(keys, hashes, types))
        .to.emit(registry, 'BatchRecorded')
        .withArgs(3n)

      expect(await registry.eventCount()).to.equal(3n)
      for (let i = 0; i < ids.length; i += 1) {
        expect(await registry.verifyEventHash(keys[i], hashes[i])).to.equal(true)
        const record = await registry.getEventRecord(keys[i])
        expect(record.eventType).to.equal(types[i])
      }
    })

    it('skips duplicates instead of overwriting them', async () => {
      await registry.recordEventHash(keys[0], hashes[0], types[0])
      const tampered = sha256('tampered-payload-a')

      await expect(registry.recordEventHashBatch(keys, [tampered, hashes[1], hashes[2]], types))
        .to.emit(registry, 'BatchRecorded')
        .withArgs(2n)

      expect(await registry.verifyEventHash(keys[0], hashes[0])).to.equal(true)
      expect(await registry.verifyEventHash(keys[0], tampered)).to.equal(false)
      expect(await registry.eventCount()).to.equal(3n)
    })

    it('rejects mismatched batch lengths', async () => {
      await expect(registry.recordEventHashBatch(keys, hashes.slice(0, 2), types))
        .to.be.revertedWith('SecurityEventRegistry: batch length mismatch')
    })

    it('is cheaper per event than individual transactions', async () => {
      const single = await registry.recordEventHash(keys[0], hashes[0], types[0])
      const singleReceipt = await single.wait()

      const fresh = await (await ethers.getContractFactory('SecurityEventRegistry')).deploy()
      const batch = await fresh.recordEventHashBatch(keys, hashes, types)
      const batchReceipt = await batch.wait()

      expect(batchReceipt.gasUsed / 3n).to.be.lessThan(singleReceipt.gasUsed)
    })
  })

  describe('ownership', () => {
    it('transfers ownership and whitelists the new owner', async () => {
      await registry.transferOwnership(recorder.address)

      expect(await registry.owner()).to.equal(recorder.address)
      expect(await registry.recorders(recorder.address)).to.equal(true)
      // Ownership transfer revokes the previous owner's anchoring rights.
      expect(await registry.recorders(owner.address)).to.equal(false)
      await expect(registry.connect(stranger).recordEventHash(eventId('x'), sha256('x'), 'alert'))
        .to.be.revertedWith('SecurityEventRegistry: caller is not authorized to record events')
    })

    it('rejects transferring to the zero address', async () => {
      await expect(registry.transferOwnership(ethers.ZeroAddress))
        .to.be.revertedWith('SecurityEventRegistry: zero address')
    })
  })

  describe('privacy guarantees', () => {
    it('never exposes payload content, only 32-byte commitments', async () => {
      const secretPayload = { alert: 'DDoS from 10.0.0.5', user: 'analyst@corp.in', password: 'never-on-chain' }
      await registry.recordEventHash(eventId(sampleId), sha256(JSON.stringify(secretPayload)), 'alert')

      const record = await registry.getEventRecord(eventId(sampleId))
      const stored = [record.eventHash, record.eventType, record.recorder, record.timestamp].join('|')

      expect(stored).to.not.include('10.0.0.5')
      expect(stored).to.not.include('analyst@corp.in')
      expect(stored).to.not.include('never-on-chain')
    })

    it('returns an empty record for unknown event ids', async () => {
      const record = await registry.getEventRecord(eventId('does-not-exist'))
      expect(record.exists).to.equal(false)
      expect(record.eventHash).to.equal(ethers.ZeroHash)
      expect(record.timestamp).to.equal(0n)
      expect(record.recorder).to.equal(ethers.ZeroAddress)
      expect(record.eventType).to.equal('')
    })
  })
})
