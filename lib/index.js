'use strict'
const secp = require('bindings')('secp256k1-zkp');
const crypto = require('crypto');
const BN = require('bn.js');

/**
 * @const {Buffer}
 */
const ZERO_8 = Buffer.alloc(8, 0);

/**
 * @const {Buffer}
 */
const ZERO_32 = Buffer.alloc(32, 0);

/**
 * @const {Buffer}
 */
const ZERO_64 = Buffer.alloc(64, 0);

/**
 * create random sha256 Buffer
 * @param {string} v
 * @return {PromiseLike<ArrayBuffer>}
 */
function sha256(v) {
    return crypto.createHmac('sha256', v).digest();
}

/**
 * Takes any number (native number, BN, or string) and
 * converts it to uInt64T (64-bit BE Buffer) suitable for
 * use by the C++ bindings.
 * @param {number} num - number to convert.
 * @return {Buffer}
 */
function uInt64T(num) {
    return (new BN(num)).toBuffer('be', 8);
}

class Secp {
    /**
     * @constructor
     * @param {{ sign: boolean, verify: boolean }} opts
     * @param {boolean} [opts.sign=true]
     * @param {boolean} [opts.verify=true]
     */
    constructor(opts = { sign: true, verify: true }) {
        const { sign, verify } = opts;
        this.secp = new secp.Secp256k1zkp(sign, verify);
    }

    /**
     * Creates an zero secret key.
     * @return {Buffer}
     */
    secretKeyZero() {
        return ZERO_32;
    }

    /**
     * Creates a secret key.
     * @param {Buffer | string} input
     * @return {Buffer}
     */
    secretKeyCreate(input) {
        input = Buffer.isBuffer(input) ? input : (new BN(input)).toBuffer('be', 32);
        // Verify the key is valid.
        if (!this.secp.ec_seckey_verify(input)) {
            throw new Error('Invalid secret key!');
        }

        // Secret key is just a 32 byte Buffer.
        return input;
    }

    /**
     * Creates a new random secret key
     * @return {Buffer}
     */
    secretKeyGenerate() {
        while (true) {
            const key = crypto.randomBytes(32);
            if (this.secp.ec_seckey_verify(key)) {
                return key;
            }
            // Try again, bad key.
        }
    }

    /**
     * Verifies validity of a secret key.
     * @param {Buffer} key
     * @return {boolean}
     */
    secretKeyVerify(key) {
        return this.secp.ec_seckey_verify(key);
    }

    /**
     * Adds two secretKeys to create a new secretKey
     * @param {Buffer} secretKey1
     * @param {Buffer} secretKey2
     * @return {Buffer}
     */
    secretKeyAdd(secretKey1, secretKey2) {
        return this.secp.ec_privkey_tweak_add(secretKey1, secretKey2);
    }

    /**
     * Adds two secretKeys to create a new secretKey
     * @param {Buffer} secretKey1
     * @param {Buffer} secretKey2
     * @return {Buffer}
     */
    secretKeymul(secretKey1, secretKey2) {
        return this.secp.ec_privkey_tweak_add(secretKey1, secretKey2);
    }

    /**
     * Creates an invalid zero public key.
     * @return {Buffer}
     */
    pubKeyZero() {
        return ZERO_64;
    }

    /**
     * Creates a new public key from a secret key.
     * @param {Buffer} secretKey
     * @return {Buffer}
     */
    pubKeyFromSecretKey(secretKey) {
        return this.secp.ec_pubkey_create(secretKey);
    }

    /**
     * Creates a new public key from the sum of the public keys.
     * @param {Buffer[]} pubKeys
     * @return {Buffer}
     */
    pubKeyFromAddingPubKeys(pubKeys) {
        return this.secp.ec_pubkey_combine(pubKeys);
    }

    /**
     * Determine if a public key is valid.
     * @param {Buffer} pubKey
     * @return {boolean}
     */
    pubKeyIsValid(pubKey) {
        return (pubKey.compare(ZERO_64) !== 0);
    }

    /**
     * Determine if a public key is zero.
     * @param {Buffer} pubKey
     * @return {boolean}
     */
    pubKeyIsZero(pubKey) {
        return (pubKey.compare(ZERO_32, 0, ZERO_32.length, 0, ZERO_32.length) === 0);
    }

    /**
     * Serializes a public key.
     * @param {Buffer} pubKey
     * @param {boolean} [compress=true]
     * @return {Buffer}
     */
    pubKeySerialize(pubKey, compress = true) {
        return this.secp.ec_pubkey_serialize(pubKey, compress);
    }

    /**
     * Parses a public key.
     * @param {Buffer} buffer
     * @return {Buffer}
     */
    pubKeyParse(buffer) {
        return this.secp.ec_pubkey_parse(buffer);
    }

    /**
     * Generates a random keyPair. Convenience function for `secretKeyGenerate`
     * and `pubKeyFromSecretKey`
     * @return {{secretKey: Buffer, pubKey: Buffer}}
     */
    keyPairGenerate() {
        const secretKey = this.secretKeyGenerate()
        const pubKey = this.pubKeyFromSecretKey(secretKey);
        return { secretKey, pubKey };
    }

    /**
     * Constructs a signature for `msg` using the secret key `secretKey` and RFC6979 nonce
     * @param {Buffer} msg
     * @param {Buffer} secretKey
     * @return {Buffer}
     */
    sign(msg, secretKey) {
        if (!Buffer.isBuffer(msg) || (msg.length !== 32)) {
            msg = sha256(msg);
        }

        return this.secp.ecdsa_sign(msg, secretKey);
    }

    /**
     * Checks that `sig` is a valid ECDSA signature for `msg` using the public
     * key `pubKey`.
     * @param {Buffer} sig
     * @param {Buffer} msg
     * @param {Buffer} pubKey
     * @return {boolean}
     */
    verify(sig, msg, pubKey) {
        if (!Buffer.isBuffer(msg) || (msg.length !== 32)) {
            msg = sha256(msg);
        }

        return this.secp.ecdsa_verify(sig, msg, pubKey);
    }

    /**
     * Serializes a signature.
     * @param {Buffer} sig
     * @return {Buffer}
     */
    signatureSerialize(sig) {
        return this.secp.ecdsa_signature_serialize_compact(sig);
    }

    /**
     * Parses a signature.
     * @param {Buffer} buffer
     * @return {Buffer}
     */
    signatureParse(buffer) {
        return this.secp.ecdsa_signature_parse_compact(buffer);
    }

    /**
     * Creates a pedersen commitment from a value and a blinding factor
     * @param {number} value
     * @param {Buffer} [blind]
     * @return {Buffer}
     */
    commit(value, blind) {
        return typeof blind === 'undefined' ?
            this.secp.pedersen_commit(uInt64T(value)) : this.secp.pedersen_commit(uInt64T(value), blind);
    }

    /**
     * Computes blinding factor for switch commitment.
     * @param {number} value
     * @param {Buffer} blind
     * @return {Buffer}
     */
    blindSwitch(value, blind) {
        return this.secp.pedersen_blind_switch(uInt64T(value), blind);
    }

    /**
     * Computes the sum of multiple positive and negative pedersen commitments.
     * @param {Buffer[]} [positives=[]]
     * @param {Buffer[]} [negatives=[]]
     * @return {Buffer}
     */
    commitSum(positives = [], negatives = []) {
        return this.secp.pedersen_commit_sum(positives, negatives);
    }

    /**
     * Taking arrays of positive and negative commitments as well as an
     * expected excess, verifies that it all sums to zero.
     * @param {Buffer[]} [positives=[]]
     * @param {Buffer[]} [negatives=[]]
     * @return {boolean}
     */
    verifyCommitSum(positives = [], negatives = []) {
        return this.secp.pedersen_verify_tally(positives, negatives);
    }

    /**
     * Computes the sum of multiple positive and negative blinding factors.
     * @param {Buffer[]} [positives=[]]
     * @param {Buffer[]} [negatives=[]]
     * @return {Buffer}
     */
    blindSum(positives = [], negatives = []) {
        return this.secp.pedersen_blind_sum(positives.concat(negatives), positives.length);
    }

    /**
     * Retrieves pubKey from commit.
     * @param {Buffer} commitment
     * @return {Buffer}
     */
    commitmentToPubKey(commitment) {
        return this.secp.pedersen_commitment_to_pubkey(commitment);
    }

    /**
     * Serializes commitment.
     * @param {Buffer} commitment
     * @return {Buffer}
     */
    commitmentSerialize(commitment) {
        return this.secp.pedersen_commitment_serialize(commitment);
    }

    /**
     * Parses a commitment.
     * @param {Buffer} buffer
     * @return {Buffer}
     */
    commitmentParse(buffer) {
        return this.secp.pedersen_commitment_parse(buffer);
    }

    /**
     * Verify commitment.
     * @param {Buffer} msg
     * @param {Buffer} sig
     * @param {Buffer} commitment
     * @return {boolean}
     */
    verifyFromCommit(msg, sig, commitment) {
        const pubKey = this.commitmentToPubKey(commitment);
        return this.verify(sig, msg, pubKey);
    }

    /**
     * Verify with bullet proof that a committed value is positive.
     * @param {Buffer} commitment
     * @param {Buffer} rangeProof
     * @param {Buffer} extraData
     * @return {boolean}
     */
    bulletProofVerify(commitment, rangeProof, extraData) {
        return this.secp.bulletproof_rangeproof_verify(rangeProof, commitment, extraData);
    }

    /**
     * Verify with bullet proof that a committed value is positive.
     * @param {Buffer} commitments
     * @param {Buffer[]} rangeProofs
     * @param {Buffer} extraData
     * @return {boolean}
     */
    bulletProofVerifyMulti(commitments, rangeProofs, extraData) {
        return this.secp.bulletproof_rangeproof_verify_multi(rangeProofs, commitments, extraData);
    }

    /**
     * Create a bulletproof.
     * The blinding factor for commitment should be secretKey.
     * @param {number} amount
     * @param {Buffer} secretKey
     * @param {Buffer} nonce
     * @param {Buffer} extraData
     * @param {Buffer} [msg=Buffer.alloc(16, 0)]
     * @return {Buffer}
     */
    bulletProofCreate(amount, secretKey, nonce, extraData, msg = Buffer.alloc(16, 0)) {
        if (msg.length < 16) {
            msg = Buffer.concat([msg, Buffer.alloc(16 - msg.length, 0)]);
        }
        msg = msg.slice(0, 16);

        return this.secp.bulletproof_rangeproof_prove(uInt64T(amount), secretKey, nonce, extraData, msg);
    }

    /**
     * Rewind a rangeProof to retrieve the amount
     * @param {number} commitment
     * @param {number} nonce
     * @param {number} extraData
     * @param {number} rangeProof
     * @return {Buffer}
     */
    bulletProofRewind(commitment, nonce, extraData, rangeProof) {
        return this.secp.bulletproof_rangeproof_rewind(rangeProof, commitment, nonce, extraData);
    }

    /**
     * Creates a new secure nonce (as a SecretKey), guaranteed to be usable during
     * aggsig creation.
     * @return {Buffer}
     */
    aggsigCreateSecnonce() {
        return this.secp.aggsig_export_secnonce_single(crypto.randomBytes(32));
    }

    /**
     * Simple signature (nonce will be created).
     * @param {Buffer} msg
     * @param {Buffer} secretKey
     * @param {Buffer} pubKeySum
     * @return {Buffer}
     */
    aggsigSignSingle(msg, secretKey, pubKeySum) {
        return this.secp.aggsig_sign_single(msg, secretKey, null, null, null, null, pubKeySum, crypto.randomBytes(32));
    }

    /**
     * Calculates a signature for msg given the secretKey and an optional blindSum
     * @param {Buffer} secretKey
     * @param {Buffer} msg
     * @param {Buffer} blindSum
     * @return {Buffer}
     */
    aggsigSignFromSecretKey(secretKey, msg, blindSum) {
        return this.secp.aggsig_sign_single(msg, secretKey, null, null, null, null, blindSum, crypto.randomBytes(32));
    }

    /**
     * Calculates a partial signature given the signer's secure key,
     * the sum of all public nonces and (optionally) the sum of all public keys.
     * @param {Buffer} secretKey - The signer's secret key
     * @param {Buffer} secNonce - The signer's secret nonce (the public version of which was added to the `nonceSum` total)
     * @param {Buffer} nonceSum - The sum of the public nonces of all signers participating
     * in the full signature. This value is encoded in e.
     * @param {Buffer} pubKeySum - (Optional) The sum of the public keys of all signers participating
     * in the full signature. If included, this value is encoded in e.
     * @param {Buffer} msg - The message to sign.
     * @return {Buffer}
     */
    aggsigCalculatePartialSig(secretKey, secNonce, nonceSum, pubKeySum, msg) {
        if (this.pubKeyIsZero(nonceSum)) {
            throw new Error('nonceSum is invalid');
        }

        if (this.pubKeyIsZero(pubKeySum)) {
            throw new Error('pubKeySum is invalid');
        }

        return this.secp.aggsig_sign_single(msg, secretKey, secNonce, null, nonceSum, nonceSum, pubKeySum, crypto.randomBytes(32));
    }

    /**
     * Single-Signer (plain old Schnorr, sans-multisig) signature verification
     * @param {Buffer} sig - The signature
     * @param {Buffer} msg - the message to verify
     * @param {Buffer} pubNonce - if not null overrides the public nonce used to calculate e
     * @param {Buffer} pubKey - the public key
     * @param {Buffer} pubKeyTotal - The total of all public keys (for the message in e)
     * @param {Buffer} extraPubKey - if not null, subtract this pubKey from sG
     * @param {boolean} isPartial - whether this is a partial sig, or a fully-combined sig
     * @return {Buffer} - Signature on success
     */
    aggsigVerifySingle(sig, msg, pubNonce, pubKey, pubKeyTotal, extraPubKey, isPartial) {
        return this.secp.aggsig_verify_single(sig, msg, pubNonce, pubKey, pubKeyTotal, extraPubKey, isPartial);
    }

    /**
     * Verifies a partial signature from a public key. All nonce and public
     * key sum values must be identical to those provided in the call to
     * [`calculate_partial_sig`].
     * @param {Buffer} sig - The signature to validate, created via a call to [`calculate_partial_sig`]
     * @param {Buffer} pubNonceSum - The sum of the public nonces of all signers participating
     * in the full signature. This value is encoded in e.
     * @param {Buffer} pubKey - Corresponding Public Key of the private key used to sign the message.
     * @param {Buffer} pubKeySum - (Optional) The sum of the public keys of all signers participating
     * in the full signature. If included, this value is encoded in e.
     * @param {Buffer} msg - The message to verify.
     * @return {Buffer}
     */
    aggsigVerifyPartialSig(sig, pubNonceSum, pubKey, pubKeySum, msg) {
        return this.aggsigVerifySingle(sig, msg, pubNonceSum, pubKey, pubKeySum, null, true);
    }

    /**
     * Simple verification a single signature from a commitment. The public
     * key used to verify the signature is derived from the commit.
     * @param {Buffer} sig - The Signature to verify
     * @param {Buffer} msg - The message to sign.
     * @param {Buffer} commit - The commitment to verify. The actual public key used
     * during verification is derived from this commit.
     * @return {Buffer}
     */
    aggsigVerifySingleFromCommit(sig, msg, commit) {
        const pubKey = this.commitmentToPubKey(commit)
        return this.aggsigVerifySingle(sig, msg, null, pubKey, pubKey, null, false);
    }

    /**
     * Verifies a completed (summed) signature, which must include the message
     * and pubKey sum values that are used during signature creation time
     * to create 'e'
     * @param {Buffer} sig - The Signature to verify
     * @param {Buffer} pubKey - Corresponding Public Key of the private key used to sign the message.
     * @param {Buffer} pubKeySum - (Optional) The sum of the public keys of all signers participating
     * in the full signature. If included, this value is encoded in e. Must be the same
     * value as when the signature was created to verify correctly.
     * @param {Buffer} msg - The message to verify.
     * @return {Buffer}
     */
    aggsigVerifyCompletedSig(sig, pubKey, pubKeySum, msg) {
        return this.aggsigVerifySingle(sig, msg, null, pubKey, pubKeySum, null, true);
    }

    /**
     * Adds signatures
     * @param {Buffer} partSigs
     * @param {Buffer} nonceSum
     * @return {Buffer}
     */
    aggsigAddSignatures(partSigs, nonceSum) {
        return this.secp.aggsig_add_signatures_single(partSigs, nonceSum);
    }
}

module.exports = Secp
