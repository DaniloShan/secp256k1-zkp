# secp256k1-zkp
[![Build Status](https://travis-ci.org/DaniloShan/secp256k1-zkp.svg?branch=master)](https://travis-ci.org/DaniloShan/secp256k1-zkp)
[![NPM](https://img.shields.io/npm/v/secp256k1-zkp.svg)](https://www.npmjs.org/package/secp256k1-zkp)

This library is under development, and, like the secp256k1-zkp C library it depends on, this is a research effort to determine an optimal API for end-users of the mimblewimble ecosystem.

## Installation

### npm

``` bash
npm install tiny-secp256k1
```

### yarn

```bash
yarn add tiny-secp256k1
```

## Classes

<dl>
<dt><a href="#Secp">Secp</a></dt>
<dd></dd>
</dl>

## Constants

<dl>
<dt><a href="#ZERO_8">ZERO_8</a> : <code>Buffer</code></dt>
<dd></dd>
<dt><a href="#ZERO_32">ZERO_32</a> : <code>Buffer</code></dt>
<dd></dd>
<dt><a href="#ZERO_64">ZERO_64</a> : <code>Buffer</code></dt>
<dd></dd>
</dl>

## Functions

<dl>
<dt><a href="#sha256">sha256(v)</a> ⇒ <code>PromiseLike.&lt;ArrayBuffer&gt;</code></dt>
<dd><p>create random sha256 Buffer</p>
</dd>
<dt><a href="#uInt64T">uInt64T(num)</a> ⇒ <code>Buffer</code></dt>
<dd><p>Takes any number (native number, BN, or string) and
converts it to uInt64T (64-bit BE Buffer) suitable for
use by the C++ bindings.</p>
</dd>
</dl>

<a name="Secp"></a>

## Secp
**Kind**: global class

* [Secp](#Secp)
    * [new Secp(opts)](#new_Secp_new)
    * [.secretKeyZero()](#Secp+secretKeyZero) ⇒ <code>Buffer</code>
    * [.secretKeyCreate(input)](#Secp+secretKeyCreate) ⇒ <code>Buffer</code>
    * [.secretKeyGenerate()](#Secp+secretKeyGenerate) ⇒ <code>Buffer</code>
    * [.secretKeyVerify(key)](#Secp+secretKeyVerify) ⇒ <code>boolean</code>
    * [.secretKeyAdd(secretKey1, secretKey2)](#Secp+secretKeyAdd) ⇒ <code>Buffer</code>
    * [.secretKeymul(secretKey1, secretKey2)](#Secp+secretKeymul) ⇒ <code>Buffer</code>
    * [.pubKeyZero()](#Secp+pubKeyZero) ⇒ <code>Buffer</code>
    * [.pubKeyFromSecretKey(secretKey)](#Secp+pubKeyFromSecretKey) ⇒ <code>Buffer</code>
    * [.pubKeyFromAddingPubKeys(pubKeys)](#Secp+pubKeyFromAddingPubKeys) ⇒ <code>Buffer</code>
    * [.pubKeyIsValid(pubKey)](#Secp+pubKeyIsValid) ⇒ <code>boolean</code>
    * [.pubKeyIsZero(pubKey)](#Secp+pubKeyIsZero) ⇒ <code>boolean</code>
    * [.pubKeySerialize(pubKey, [compress])](#Secp+pubKeySerialize) ⇒ <code>Buffer</code>
    * [.pubKeyParse(buffer)](#Secp+pubKeyParse) ⇒ <code>Buffer</code>
    * [.keyPairGenerate()](#Secp+keyPairGenerate) ⇒ <code>Object</code>
    * [.sign(msg, secretKey)](#Secp+sign) ⇒ <code>Buffer</code>
    * [.verify(sig, msg, pubKey)](#Secp+verify) ⇒ <code>boolean</code>
    * [.signatureSerialize(sig)](#Secp+signatureSerialize) ⇒ <code>Buffer</code>
    * [.signatureParse(buffer)](#Secp+signatureParse) ⇒ <code>Buffer</code>
    * [.commit(value, [blind])](#Secp+commit) ⇒ <code>Buffer</code>
    * [.blindSwitch(value, blind)](#Secp+blindSwitch) ⇒ <code>Buffer</code>
    * [.commitSum([positives], [negatives])](#Secp+commitSum) ⇒ <code>Buffer</code>
    * [.verifyCommitSum([positives], [negatives])](#Secp+verifyCommitSum) ⇒ <code>boolean</code>
    * [.blindSum([positives], [negatives])](#Secp+blindSum) ⇒ <code>Buffer</code>
    * [.commitmentToPubKey(commitment)](#Secp+commitmentToPubKey) ⇒ <code>Buffer</code>
    * [.commitmentSerialize(commitment)](#Secp+commitmentSerialize) ⇒ <code>Buffer</code>
    * [.commitmentParse(buffer)](#Secp+commitmentParse) ⇒ <code>Buffer</code>
    * [.verifyFromCommit(msg, sig, commitment)](#Secp+verifyFromCommit) ⇒ <code>boolean</code>
    * [.bulletProofVerify(commitment, rangeProof, extraData)](#Secp+bulletProofVerify) ⇒ <code>boolean</code>
    * [.bulletProofVerifyMulti(commitments, rangeProofs, extraData)](#Secp+bulletProofVerifyMulti) ⇒ <code>boolean</code>
    * [.bulletProofCreate(amount, secretKey, nonce, extraData, [msg])](#Secp+bulletProofCreate) ⇒ <code>Buffer</code>
    * [.bulletProofRewind(commitment, nonce, extraData, rangeProof)](#Secp+bulletProofRewind) ⇒ <code>Buffer</code>
    * [.aggsigCreateSecnonce()](#Secp+aggsigCreateSecnonce) ⇒ <code>Buffer</code>
    * [.aggsigSignSingle(msg, secretKey, pubKeySum)](#Secp+aggsigSignSingle) ⇒ <code>Buffer</code>
    * [.aggsigSignFromSecretKey(secretKey, msg, blindSum)](#Secp+aggsigSignFromSecretKey) ⇒ <code>Buffer</code>
    * [.aggsigCalculatePartialSig(secretKey, secNonce, nonceSum, pubKeySum, msg)](#Secp+aggsigCalculatePartialSig) ⇒ <code>Buffer</code>
    * [.aggsigVerifySingle(sig, msg, pubNonce, pubKey, pubKeyTotal, extraPubKey, isPartial)](#Secp+aggsigVerifySingle) ⇒ <code>Buffer</code>
    * [.aggsigVerifyPartialSig(sig, pubNonceSum, pubKey, pubKeySum, msg)](#Secp+aggsigVerifyPartialSig) ⇒ <code>Buffer</code>
    * [.aggsigVerifySingleFromCommit(sig, msg, commit)](#Secp+aggsigVerifySingleFromCommit) ⇒ <code>Buffer</code>
    * [.aggsigVerifyCompletedSig(sig, pubKey, pubKeySum, msg)](#Secp+aggsigVerifyCompletedSig) ⇒ <code>Buffer</code>
    * [.aggsigAddSignatures(partSigs, nonceSum)](#Secp+aggsigAddSignatures) ⇒ <code>Buffer</code>

<a name="new_Secp_new"></a>

### new Secp(opts)

| Param | Type | Default |
| --- | --- | --- |
| opts | <code>Object</code> |  |
| [opts.sign] | <code>boolean</code> | <code>true</code> |
| [opts.verify] | <code>boolean</code> | <code>true</code> |

<a name="Secp+secretKeyZero"></a>

### secp.secretKeyZero() ⇒ <code>Buffer</code>
Creates an zero secret key.

**Kind**: instance method of [<code>Secp</code>](#Secp)
<a name="Secp+secretKeyCreate"></a>

### secp.secretKeyCreate(input) ⇒ <code>Buffer</code>
Creates a secret key.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| input | <code>Buffer</code> \| <code>string</code> |

<a name="Secp+secretKeyGenerate"></a>

### secp.secretKeyGenerate() ⇒ <code>Buffer</code>
Creates a new random secret key

**Kind**: instance method of [<code>Secp</code>](#Secp)
<a name="Secp+secretKeyVerify"></a>

### secp.secretKeyVerify(key) ⇒ <code>boolean</code>
Verifies validity of a secret key.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| key | <code>Buffer</code> |

<a name="Secp+secretKeyAdd"></a>

### secp.secretKeyAdd(secretKey1, secretKey2) ⇒ <code>Buffer</code>
Adds two secretKeys to create a new secretKey

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| secretKey1 | <code>Buffer</code> |
| secretKey2 | <code>Buffer</code> |

<a name="Secp+secretKeymul"></a>

### secp.secretKeymul(secretKey1, secretKey2) ⇒ <code>Buffer</code>
Adds two secretKeys to create a new secretKey

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| secretKey1 | <code>Buffer</code> |
| secretKey2 | <code>Buffer</code> |

<a name="Secp+pubKeyZero"></a>

### secp.pubKeyZero() ⇒ <code>Buffer</code>
Creates an invalid zero public key.

**Kind**: instance method of [<code>Secp</code>](#Secp)
<a name="Secp+pubKeyFromSecretKey"></a>

### secp.pubKeyFromSecretKey(secretKey) ⇒ <code>Buffer</code>
Creates a new public key from a secret key.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| secretKey | <code>Buffer</code> |

<a name="Secp+pubKeyFromAddingPubKeys"></a>

### secp.pubKeyFromAddingPubKeys(pubKeys) ⇒ <code>Buffer</code>
Creates a new public key from the sum of the public keys.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| pubKeys | <code>Array.&lt;Buffer&gt;</code> |

<a name="Secp+pubKeyIsValid"></a>

### secp.pubKeyIsValid(pubKey) ⇒ <code>boolean</code>
Determine if a public key is valid.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| pubKey | <code>Buffer</code> |

<a name="Secp+pubKeyIsZero"></a>

### secp.pubKeyIsZero(pubKey) ⇒ <code>boolean</code>
Determine if a public key is zero.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| pubKey | <code>Buffer</code> |

<a name="Secp+pubKeySerialize"></a>

### secp.pubKeySerialize(pubKey, [compress]) ⇒ <code>Buffer</code>
Serializes a public key.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Default |
| --- | --- | --- |
| pubKey | <code>Buffer</code> |  |
| [compress] | <code>boolean</code> | <code>true</code> |

<a name="Secp+pubKeyParse"></a>

### secp.pubKeyParse(buffer) ⇒ <code>Buffer</code>
Parses a public key.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| buffer | <code>Buffer</code> |

<a name="Secp+keyPairGenerate"></a>

### secp.keyPairGenerate() ⇒ <code>Object</code>
Generates a random keyPair. Convenience function for `secretKeyGenerate`
and `pubKeyFromSecretKey`

**Kind**: instance method of [<code>Secp</code>](#Secp)
<a name="Secp+sign"></a>

### secp.sign(msg, secretKey) ⇒ <code>Buffer</code>
Constructs a signature for `msg` using the secret key `secretKey` and RFC6979 nonce

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| msg | <code>Buffer</code> |
| secretKey | <code>Buffer</code> |

<a name="Secp+verify"></a>

### secp.verify(sig, msg, pubKey) ⇒ <code>boolean</code>
Checks that `sig` is a valid ECDSA signature for `msg` using the public
key `pubKey`.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| sig | <code>Buffer</code> |
| msg | <code>Buffer</code> |
| pubKey | <code>Buffer</code> |

<a name="Secp+signatureSerialize"></a>

### secp.signatureSerialize(sig) ⇒ <code>Buffer</code>
Serializes a signature.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| sig | <code>Buffer</code> |

<a name="Secp+signatureParse"></a>

### secp.signatureParse(buffer) ⇒ <code>Buffer</code>
Parses a signature.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| buffer | <code>Buffer</code> |

<a name="Secp+commit"></a>

### secp.commit(value, [blind]) ⇒ <code>Buffer</code>
Creates a pedersen commitment from a value and a blinding factor

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| value | <code>number</code> |
| [blind] | <code>Buffer</code> |

<a name="Secp+blindSwitch"></a>

### secp.blindSwitch(value, blind) ⇒ <code>Buffer</code>
Computes blinding factor for switch commitment.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| value | <code>number</code> |
| blind | <code>Buffer</code> |

<a name="Secp+commitSum"></a>

### secp.commitSum([positives], [negatives]) ⇒ <code>Buffer</code>
Computes the sum of multiple positive and negative pedersen commitments.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Default |
| --- | --- | --- |
| [positives] | <code>Array.&lt;Buffer&gt;</code> | <code>[]</code> |
| [negatives] | <code>Array.&lt;Buffer&gt;</code> | <code>[]</code> |

<a name="Secp+verifyCommitSum"></a>

### secp.verifyCommitSum([positives], [negatives]) ⇒ <code>boolean</code>
Taking arrays of positive and negative commitments as well as an
expected excess, verifies that it all sums to zero.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Default |
| --- | --- | --- |
| [positives] | <code>Array.&lt;Buffer&gt;</code> | <code>[]</code> |
| [negatives] | <code>Array.&lt;Buffer&gt;</code> | <code>[]</code> |

<a name="Secp+blindSum"></a>

### secp.blindSum([positives], [negatives]) ⇒ <code>Buffer</code>
Computes the sum of multiple positive and negative blinding factors.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Default |
| --- | --- | --- |
| [positives] | <code>Array.&lt;Buffer&gt;</code> | <code>[]</code> |
| [negatives] | <code>Array.&lt;Buffer&gt;</code> | <code>[]</code> |

<a name="Secp+commitmentToPubKey"></a>

### secp.commitmentToPubKey(commitment) ⇒ <code>Buffer</code>
Retrieves pubKey from commit.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| commitment | <code>Buffer</code> |

<a name="Secp+commitmentSerialize"></a>

### secp.commitmentSerialize(commitment) ⇒ <code>Buffer</code>
Serializes commitment.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| commitment | <code>Buffer</code> |

<a name="Secp+commitmentParse"></a>

### secp.commitmentParse(buffer) ⇒ <code>Buffer</code>
Parses a commitment.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| buffer | <code>Buffer</code> |

<a name="Secp+verifyFromCommit"></a>

### secp.verifyFromCommit(msg, sig, commitment) ⇒ <code>boolean</code>
Verify commitment.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| msg | <code>Buffer</code> |
| sig | <code>Buffer</code> |
| commitment | <code>Buffer</code> |

<a name="Secp+bulletProofVerify"></a>

### secp.bulletProofVerify(commitment, rangeProof, extraData) ⇒ <code>boolean</code>
Verify with bullet proof that a committed value is positive.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| commitment | <code>Buffer</code> |
| rangeProof | <code>Buffer</code> |
| extraData | <code>Buffer</code> |

<a name="Secp+bulletProofVerifyMulti"></a>

### secp.bulletProofVerifyMulti(commitments, rangeProofs, extraData) ⇒ <code>boolean</code>
Verify with bullet proof that a committed value is positive.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| commitments | <code>Buffer</code> |
| rangeProofs | <code>Array.&lt;Buffer&gt;</code> |
| extraData | <code>Buffer</code> |

<a name="Secp+bulletProofCreate"></a>

### secp.bulletProofCreate(amount, secretKey, nonce, extraData, [msg]) ⇒ <code>Buffer</code>
Create a bulletproof.
The blinding factor for commitment should be secretKey.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Default |
| --- | --- | --- |
| amount | <code>number</code> |  |
| secretKey | <code>Buffer</code> |  |
| nonce | <code>Buffer</code> |  |
| extraData | <code>Buffer</code> |  |
| [msg] | <code>Buffer</code> | <code>Buffer.alloc(16, 0)</code> |

<a name="Secp+bulletProofRewind"></a>

### secp.bulletProofRewind(commitment, nonce, extraData, rangeProof) ⇒ <code>Buffer</code>
Rewind a rangeProof to retrieve the amount

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| commitment | <code>number</code> |
| nonce | <code>number</code> |
| extraData | <code>number</code> |
| rangeProof | <code>number</code> |

<a name="Secp+aggsigCreateSecnonce"></a>

### secp.aggsigCreateSecnonce() ⇒ <code>Buffer</code>
Creates a new secure nonce (as a SecretKey), guaranteed to be usable during
aggsig creation.

**Kind**: instance method of [<code>Secp</code>](#Secp)
<a name="Secp+aggsigSignSingle"></a>

### secp.aggsigSignSingle(msg, secretKey, pubKeySum) ⇒ <code>Buffer</code>
Simple signature (nonce will be created).

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| msg | <code>Buffer</code> |
| secretKey | <code>Buffer</code> |
| pubKeySum | <code>Buffer</code> |

<a name="Secp+aggsigSignFromSecretKey"></a>

### secp.aggsigSignFromSecretKey(secretKey, msg, blindSum) ⇒ <code>Buffer</code>
Calculates a signature for msg given the secretKey and an optional blindSum

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| secretKey | <code>Buffer</code> |
| msg | <code>Buffer</code> |
| blindSum | <code>Buffer</code> |

<a name="Secp+aggsigCalculatePartialSig"></a>

### secp.aggsigCalculatePartialSig(secretKey, secNonce, nonceSum, pubKeySum, msg) ⇒ <code>Buffer</code>
Calculates a partial signature given the signer's secure key,
the sum of all public nonces and (optionally) the sum of all public keys.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Description |
| --- | --- | --- |
| secretKey | <code>Buffer</code> | The signer's secret key |
| secNonce | <code>Buffer</code> | The signer's secret nonce (the public version of which was added to the `nonceSum` total) |
| nonceSum | <code>Buffer</code> | The sum of the public nonces of all signers participating in the full signature. This value is encoded in e. |
| pubKeySum | <code>Buffer</code> | (Optional) The sum of the public keys of all signers participating in the full signature. If included, this value is encoded in e. |
| msg | <code>Buffer</code> | The message to sign. |

<a name="Secp+aggsigVerifySingle"></a>

### secp.aggsigVerifySingle(sig, msg, pubNonce, pubKey, pubKeyTotal, extraPubKey, isPartial) ⇒ <code>Buffer</code>
Single-Signer (plain old Schnorr, sans-multisig) signature verification

**Kind**: instance method of [<code>Secp</code>](#Secp)
**Returns**: <code>Buffer</code> - - Signature on success

| Param | Type | Description |
| --- | --- | --- |
| sig | <code>Buffer</code> | The signature |
| msg | <code>Buffer</code> | the message to verify |
| pubNonce | <code>Buffer</code> | if not null overrides the public nonce used to calculate e |
| pubKey | <code>Buffer</code> | the public key |
| pubKeyTotal | <code>Buffer</code> | The total of all public keys (for the message in e) |
| extraPubKey | <code>Buffer</code> | if not null, subtract this pubKey from sG |
| isPartial | <code>boolean</code> | whether this is a partial sig, or a fully-combined sig |

<a name="Secp+aggsigVerifyPartialSig"></a>

### secp.aggsigVerifyPartialSig(sig, pubNonceSum, pubKey, pubKeySum, msg) ⇒ <code>Buffer</code>
Verifies a partial signature from a public key. All nonce and public
key sum values must be identical to those provided in the call to
[`calculate_partial_sig`].

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Description |
| --- | --- | --- |
| sig | <code>Buffer</code> | The signature to validate, created via a call to [`calculate_partial_sig`] |
| pubNonceSum | <code>Buffer</code> | The sum of the public nonces of all signers participating in the full signature. This value is encoded in e. |
| pubKey | <code>Buffer</code> | Corresponding Public Key of the private key used to sign the message. |
| pubKeySum | <code>Buffer</code> | (Optional) The sum of the public keys of all signers participating in the full signature. If included, this value is encoded in e. |
| msg | <code>Buffer</code> | The message to verify. |

<a name="Secp+aggsigVerifySingleFromCommit"></a>

### secp.aggsigVerifySingleFromCommit(sig, msg, commit) ⇒ <code>Buffer</code>
Simple verification a single signature from a commitment. The public
key used to verify the signature is derived from the commit.

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Description |
| --- | --- | --- |
| sig | <code>Buffer</code> | The Signature to verify |
| msg | <code>Buffer</code> | The message to sign. |
| commit | <code>Buffer</code> | The commitment to verify. The actual public key used during verification is derived from this commit. |

<a name="Secp+aggsigVerifyCompletedSig"></a>

### secp.aggsigVerifyCompletedSig(sig, pubKey, pubKeySum, msg) ⇒ <code>Buffer</code>
Verifies a completed (summed) signature, which must include the message
and pubKey sum values that are used during signature creation time
to create 'e'

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type | Description |
| --- | --- | --- |
| sig | <code>Buffer</code> | The Signature to verify |
| pubKey | <code>Buffer</code> | Corresponding Public Key of the private key used to sign the message. |
| pubKeySum | <code>Buffer</code> | (Optional) The sum of the public keys of all signers participating in the full signature. If included, this value is encoded in e. Must be the same value as when the signature was created to verify correctly. |
| msg | <code>Buffer</code> | The message to verify. |

<a name="Secp+aggsigAddSignatures"></a>

### secp.aggsigAddSignatures(partSigs, nonceSum) ⇒ <code>Buffer</code>
Adds signatures

**Kind**: instance method of [<code>Secp</code>](#Secp)

| Param | Type |
| --- | --- |
| partSigs | <code>Buffer</code> |
| nonceSum | <code>Buffer</code> |

<a name="ZERO_8"></a>

## ZERO\_8 : <code>Buffer</code>
**Kind**: global constant
<a name="ZERO_32"></a>

## ZERO\_32 : <code>Buffer</code>
**Kind**: global constant
<a name="ZERO_64"></a>

## ZERO\_64 : <code>Buffer</code>
**Kind**: global constant
<a name="sha256"></a>

## sha256(v) ⇒ <code>PromiseLike.&lt;ArrayBuffer&gt;</code>
create random sha256 Buffer

**Kind**: global function

| Param | Type |
| --- | --- |
| v | <code>string</code> |

<a name="uInt64T"></a>

## uInt64T(num) ⇒ <code>Buffer</code>
Takes any number (native number, BN, or string) and
converts it to uInt64T (64-bit BE Buffer) suitable for
use by the C++ bindings.

**Kind**: global function

| Param | Type | Description |
| --- | --- | --- |
| num | <code>number</code> | number to convert. |

