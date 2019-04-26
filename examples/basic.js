const Secp256k1zkp = require('../lib')
const BN = require('bn.js')

function int64_t(num) {
  num = new BN(num)
  if (num.isNeg()) {
    // Compute 2's completement since BN.toBuffer() does not seem to do it!
    num = (new BN(2).pow(new BN(64))).sub(num.abs())
  }
  return (new BN(num)).toBuffer('be', 8)
}

function uint256_t(num) {
  return (new BN(num)).toBuffer('be', 32)
}

const secp = Secp256k1zkp.create()

const keypair = secp.keypair_generate()

console.log(
  secp.verify_commit_sum(
    [],
    [])
)

console.log(
  secp.verify_commit_sum(
    [secp.commit(2), secp.commit(3)],
    [secp.commit(5)])
)

console.log(
  secp.verify_commit_sum(
    [secp.commit(2), secp.commit(4)],
    [secp.commit(1), secp.commit(5)])
)

console.log(
  secp.verify_commit_sum(
    [secp.commit(5, uint256_t(1))],
    [secp.commit(5, uint256_t(1))])
)

console.log(
  secp.verify_commit_sum(
    [secp.commit(2, uint256_t(1)), secp.commit(3, uint256_t(1))],
    [secp.commit(5, uint256_t(1))])
)

console.log(
  secp.verify_commit_sum(
    [secp.commit(2), secp.commit(3)],
    [secp.commit(5)])
)

console.log(
  secp.verify_commit_sum(
    [secp.commit(2, uint256_t(0)), secp.commit(3, uint256_t(0))],
    [secp.commit(5, uint256_t(0))])
)



const twokey = secp.blind_sum([uint256_t(0), uint256_t(0)])

console.log(
  secp.verify_commit_sum(
    [secp.commit(2, uint256_t(0)), secp.commit(3, uint256_t(0))], 
    [secp.commit(5, twokey)])
)

