/* eslint-disable no-console */
const fs = require('fs')
const path = require('path')
const solc = require('solc')

/**
 * Offline compiler: produces the exact artifact layout Hardhat uses, so the
 * FastAPI backend (backend/app/blockchain/contract.py) can load the ABI from
 * `blockchain/artifacts/...` without anyone running `hardhat compile`.
 *
 * `hardhat compile` needs to download the native solc binary from
 * binaries.soliditylang.org. This script uses the `solc` npm package (compiler
 * shipped inside node_modules) instead, which works with no outbound access:
 *
 *   npm run compile:offline
 *
 * The generated files:
 *   artifacts/contracts/SecurityEventRegistry.sol/SecurityEventRegistry.json
 *   artifacts/build-info/<hash>.json
 */

const ROOT = path.join(__dirname, '..')
const CONTRACT_NAME = 'SecurityEventRegistry'
const SOURCE_NAME = `contracts/${CONTRACT_NAME}.sol`
const SOURCE_PATH = path.join(ROOT, SOURCE_NAME)
const VERSION = '0.8.24'

function loadSources() {
  const sources = {}
  const walk = (dir, prefix) => {
    fs.readdirSync(dir, { withFileTypes: true }).forEach((entry) => {
      const absolute = path.join(dir, entry.name)
      const relative = `${prefix}/${entry.name}`.replace(/^\/+/, '')
      if (entry.isDirectory()) walk(absolute, relative)
      else if (entry.name.endsWith('.sol')) sources[relative] = { content: fs.readFileSync(absolute, 'utf8') }
    })
  }
  walk(path.join(ROOT, 'contracts'), 'contracts')
  return sources
}

function main() {
  if (!fs.existsSync(SOURCE_PATH)) throw new Error(`Missing contract source: ${SOURCE_PATH}`)

  console.log(`solc-js version : ${solc.version()}`)
  const sources = loadSources()
  console.log(`sources         : ${Object.keys(sources).join(', ')}`)

  const input = {
    language: 'Solidity',
    sources,
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'paris',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object', 'metadata', 'storageLayout'] } },
    },
  }

  const output = JSON.parse(solc.compile(JSON.stringify(input)))

  const errors = (output.errors || []).filter((entry) => entry.severity === 'error')
  const warnings = (output.errors || []).filter((entry) => entry.severity !== 'error')
  warnings.forEach((warning) => console.warn(`warning: ${warning.formattedMessage || warning.message}`))
  if (errors.length) {
    errors.forEach((error) => console.error(error.formattedMessage || error.message))
    throw new Error(`Compilation failed with ${errors.length} error(s).`)
  }

  const compiled = output.contracts?.[SOURCE_NAME]?.[CONTRACT_NAME]
  if (!compiled) throw new Error(`${CONTRACT_NAME} was not found in the compiler output.`)

  const artifactDir = path.join(ROOT, 'artifacts', SOURCE_NAME)
  const buildInfoDir = path.join(ROOT, 'artifacts', 'build-info')
  fs.mkdirSync(artifactDir, { recursive: true })
  fs.mkdirSync(buildInfoDir, { recursive: true })

  const buildInfoHash = require('crypto').createHash('sha256').update(JSON.stringify(input)).digest('hex').slice(0, 32)
  const buildInfoFile = path.join(buildInfoDir, `${buildInfoHash}.json`)
  fs.writeFileSync(buildInfoFile, JSON.stringify({ id: buildInfoHash, solcVersion: VERSION, solcLongVersion: solc.version(), input, output: { contracts: output.contracts, sources: output.sources } }, null, 2))

  const artifact = {
    _format: 'hh-sol-artifact-1',
    contractName: CONTRACT_NAME,
    sourceName: SOURCE_NAME,
    abi: compiled.abi,
    bytecode: `0x${compiled.evm.bytecode.object}`,
    deployedBytecode: `0x${compiled.evm.deployedBytecode.object}`,
    linkReferences: {},
    deployedLinkReferences: {},
    storageLayout: compiled.storageLayout,
    compiler: { version: solc.version() },
    solcjsBuild: true,
    builtAt: new Date().toISOString(),
  }
  const artifactFile = path.join(artifactDir, `${CONTRACT_NAME}.json`)
  fs.writeFileSync(artifactFile, JSON.stringify(artifact, null, 2))
  fs.writeFileSync(path.join(artifactDir, `${CONTRACT_NAME}.dbg.json`), JSON.stringify({ _format: 'hh-sol-dbg-1', buildInfo: `../../build-info/${buildInfoHash}.json` }, null, 2))

  const functions = compiled.abi.filter((entry) => entry.type === 'function').map((entry) => entry.name)
  const events = compiled.abi.filter((entry) => entry.type === 'event').map((entry) => entry.name)

  console.log(`\ncompiled ${CONTRACT_NAME} (${VERSION}, optimizer 200 runs)`)
  console.log(`  bytecode   : ${(artifact.bytecode.length - 2) / 2} bytes`)
  console.log(`  functions  : ${functions.join(', ')}`)
  console.log(`  events     : ${events.join(', ')}`)
  console.log(`  artifact   : ${path.relative(ROOT, artifactFile)}`)
  console.log(`  build info : ${path.relative(ROOT, buildInfoFile)}`)
  console.log('\nThe backend now reports abi_source = "hardhat-artifact" on GET /api/blockchain/contract.')
}

main()
