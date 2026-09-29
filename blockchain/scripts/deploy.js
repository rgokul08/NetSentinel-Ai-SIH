/* eslint-disable no-console */
const fs = require('fs')
const path = require('path')
const { ethers, network } = require('hardhat')

/**
 * Deploy SecurityEventRegistry and persist the deployment record.
 *
 *   npx hardhat run scripts/deploy.js                 # in-process Hardhat network
 *   npx hardhat run scripts/deploy.js --network localhost
 *   npx hardhat run scripts/deploy.js --network amoy
 *
 * Output: blockchain/deployments/<network>.json plus the exact backend .env
 * lines needed to switch CyberForecast AI from local-hash-chain mode to EVM
 * anchoring.
 */
async function main() {
  const [deployer] = await ethers.getSigners()
  if (!deployer) {
    throw new Error('No signer available. Set BLOCKCHAIN_PRIVATE_KEY in blockchain/.env for public networks.')
  }

  console.log(`Network        : ${network.name} (chainId ${network.config.chainId ?? 'n/a'})`)
  console.log(`RPC            : ${network.config.url || 'in-process'}`)
  console.log(`Deployer       : ${deployer.address}`)
  console.log(`Balance        : ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))}`)

  const factory = await ethers.getContractFactory('SecurityEventRegistry')
  const registry = await factory.deploy()
  await registry.waitForDeployment()

  const address = await registry.getAddress()
  const tx = registry.deploymentTransaction()
  const receipt = await tx?.wait()

  console.log(`\nSecurityEventRegistry deployed at ${address}`)
  console.log(`Deployment tx  : ${tx?.hash ?? 'n/a'} (block ${receipt?.blockNumber ?? 'n/a'}, gas ${receipt?.gasUsed ?? 'n/a'})`)
  console.log(`Owner / recorder: ${await registry.owner()}`)
  console.log(`Event count    : ${await registry.eventCount()}`)

  const deploymentsDir = path.join(__dirname, '..', 'deployments')
  fs.mkdirSync(deploymentsDir, { recursive: true })
  const record = {
    network: network.name,
    chainId: Number(network.config.chainId ?? 31337),
    contract: 'SecurityEventRegistry',
    address,
    deployer: deployer.address,
    owner: await registry.owner(),
    transactionHash: tx?.hash ?? null,
    blockNumber: receipt?.blockNumber ?? null,
    gasUsed: receipt?.gasUsed ? String(receipt.gasUsed) : null,
    rpcUrl: network.config.url || 'in-process',
    deployedAt: new Date().toISOString(),
    artifact: 'blockchain/artifacts/contracts/SecurityEventRegistry.sol/SecurityEventRegistry.json',
    notes: 'Only event hashes are stored on-chain. The backend keeps the local hash chain authoritative.',
  }
  const outFile = path.join(deploymentsDir, `${network.name}.json`)
  fs.writeFileSync(outFile, `${JSON.stringify(record, null, 2)}\n`)
  console.log(`\nDeployment record written to ${path.relative(process.cwd(), outFile)}`)

  console.log('\n--- add these to backend/.env to enable EVM anchoring ---')
  console.log(`BLOCKCHAIN_ANCHOR_ENABLED=true`)
  console.log(`BLOCKCHAIN_CONTRACT_ADDRESS=${address}`)
  console.log(`BLOCKCHAIN_CHAIN_ID=${record.chainId}`)
  console.log(`BLOCKCHAIN_RPC_URL=${record.rpcUrl === 'in-process' ? 'http://127.0.0.1:8545' : record.rpcUrl}`)
  console.log('BLOCKCHAIN_PRIVATE_KEY=<hex private key of an authorized recorder address>')
  console.log('\nIf the recorder address is not the owner, whitelist it once:')
  console.log(`  npx hardhat console --network ${network.name}`)
  console.log(`  > const r = await ethers.getContractAt("SecurityEventRegistry", "${address}")`)
  console.log('  > await (await r.setRecorder("<recorder-address>", true)).wait()')
  console.log('\nRestart the FastAPI backend; /api/blockchain/status will report anchor mode "evm".')
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
