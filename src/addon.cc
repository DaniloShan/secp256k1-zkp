#include <memory>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <nan.h>
#include <node.h>
#include <secp256k1.h>
#include <secp256k1_commitment.h>
#include <secp256k1_generator.h>
#include <secp256k1_bulletproofs.h>
#include <secp256k1_aggsig.h>

#include "utils.h"

#define SCRATCH_SPACE_SIZE ((1 << 20) * 256)
#define MAX_GENERATORS (256)
#define SINGLE_BULLET_PROOF_SIZE (675)

static secp256k1_pubkey GENERATOR_J_PUB = { 
  {
    0x5f, 0x15, 0x21, 0x36, 0x93, 0x93, 0x01, 0x2a,
    0x8d, 0x8b, 0x39, 0x7e, 0x9b, 0xf4, 0x54, 0x29,
    0x2f, 0x5a, 0x1b, 0x3d, 0x38, 0x85, 0x16, 0xc2,
    0xf3, 0x03, 0xfc, 0x95, 0x67, 0xf5, 0x60, 0xb8,
    0x3a, 0xc4, 0xc5, 0xa6, 0xdc, 0xa2, 0x01, 0x59,
    0xfc, 0x56, 0xcf, 0x74, 0x9a, 0xa6, 0xa5, 0x65,
    0x31, 0x6a, 0xa5, 0x03, 0x74, 0x42, 0x3f, 0x42,
    0x53, 0x8f, 0xaa, 0x2c, 0xd3, 0x09, 0x3f, 0xa4
  }
};
    
static void dumphex(std::ostream &strm, unsigned char *buf, size_t len) {
  // Hex print and restore default afterwards.
  std::ios state(nullptr);
  state.copyfmt(strm);
  for (size_t i = 0; i < len; ++i) {
    strm << std::hex << std::setfill('0') << std::setw(2);
    strm << (unsigned int)buf[i] << " ";
  }
  strm << std::endl;
  strm.copyfmt(state);
}

class Secp256k1zkp : public Nan::ObjectWrap{
  static Nan::Persistent<v8::FunctionTemplate> constructor;

  explicit Secp256k1zkp(bool sign, bool verify) {
    unsigned int flags = SECP256K1_CONTEXT_NONE;

    if (sign) {
      flags |= SECP256K1_CONTEXT_SIGN;
    }
    if (verify) {
      flags |= SECP256K1_CONTEXT_VERIFY;
    }

    this->ctx = secp256k1_context_create(flags);
    this->bulletproof_generators = secp256k1_bulletproof_generators_create(this->ctx, &secp256k1_generator_const_g, MAX_GENERATORS);
  }

  virtual ~Secp256k1zkp() {
    secp256k1_bulletproof_generators_destroy(this->ctx, this->bulletproof_generators);
    this->bulletproof_generators = NULL;
    secp256k1_context_destroy(this->ctx);
    this->ctx = NULL;

    std::cerr << "Destructed!" << std::endl;
  }

  static NAN_METHOD(New) {
    if (!info.IsConstructCall()) {
      THROW_ERROR("Secp256k1zkp::New called without new keyword");
    }

    bool sign = true;
    bool verify = true;
    
    if (info.Length() != 0) {
      if (info.Length() != 2) {
        THROW_ERROR("Secp256k1zkp::New called with wrong number of arguments");
      }
      if (!info[0]->IsUndefined()) {
        sign = info[0]->IsTrue();
      }

      if (!info[1]->IsUndefined()) {
        verify = info[1]->IsTrue();
      }
    }

    Secp256k1zkp *obj = new Secp256k1zkp(sign, verify);
    obj->Wrap(info.Holder());
    
    RETURN_THIS();
  }

  static NAN_METHOD(ec_pubkey_parse) {
    GET_HOLDER(This);
    
    if (info.Length() != 1) {
      THROW_ERROR("ec_pubkey_parse called with wrong number of arguments");
    }

    GET_BUFFER(buffer, info[0], "buffer needs to of type Buffer");
    
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_parse(This->ctx, &pubkey, buffer, buffer_length)) {
      THROW_ERROR("secp256k1_ec_pubkey_parse failed");
    }

    RETURN_PUBKEY(pubkey);
  }

  static NAN_METHOD(ec_pubkey_serialize) {
    GET_HOLDER(This);

    if (info.Length() != 1 && info.Length() != 2) {
      THROW_ERROR("ec_pubkey_serialize called with wrong number of arguments");
    }

    GET_PUBKEY(pubkey, info[0]);

    unsigned int flags = SECP256K1_EC_COMPRESSED;
    if (info.Length() == 2) {
      if (!info[1]->IsTrue()) {
        flags = SECP256K1_EC_UNCOMPRESSED;
      }
    }

    unsigned char buffer[128];
    size_t buffer_length = 128;
    if (!secp256k1_ec_pubkey_serialize(This->ctx, buffer, &buffer_length, &pubkey, flags)) {
      THROW_ERROR("secp256k1_ec_pubkey_serialize failed");
    }

    RETURN_BUFFER(buffer, buffer_length);
  }

  static NAN_METHOD(ecdsa_signature_parse_compact) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("ecdsa_signature_parse_compact called with wrong number of arguments");
    }

    GET_BUFFER_LENGTH(buffer, info[0], 64, "buffer needs to be a Buffer of length 64");

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_compact(This->ctx, &signature, buffer)) {
      THROW_ERROR("secp256k1_ecdsa_signature_parse_compact failed");
    }

    RETURN_ECDSA_SIGNATURE(signature);
  }

  static NAN_METHOD(ecdsa_signature_parse_der) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("ecdsa_signature_parse_der called with wrong number of arguments");
    }

    GET_BUFFER(buffer, info[0], "buffer needs to be a Buffer");

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_der(This->ctx, &signature, buffer, buffer_length)) {
      THROW_ERROR("secp256k1_ecdsa_signature_parse_der failed");
    }

    RETURN_ECDSA_SIGNATURE(signature);
  }

  static NAN_METHOD(ecdsa_signature_serialize_der) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("ecdsa_signature_serialize_der called with wrong number of arguments");
    }

    GET_ECDSA_SIGNATURE(signature, info[0]);

    unsigned char buffer[128];
    size_t buffer_length = 128;
  
    if (!secp256k1_ecdsa_signature_serialize_der(This->ctx, buffer, &buffer_length, &signature)) {
      THROW_ERROR("secp256k1_ecdsa_signature_serialize_der failed");
    }

    RETURN_BUFFER(buffer, buffer_length);
  }

  static NAN_METHOD(ecdsa_signature_serialize_compact) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("ecdsa_signature_serialize_compact called with wrong number of arguments");
    }

    GET_ECDSA_SIGNATURE(signature, info[0]);

    unsigned char buffer[64];
 
    if (!secp256k1_ecdsa_signature_serialize_compact(This->ctx, buffer, &signature)) {
      THROW_ERROR("secp256k1_ecdsa_signature_serialize_compact failed");
    }

    RETURN_BUFFER(buffer, 64);
  }

  static NAN_METHOD(ecdsa_verify) {
    GET_HOLDER(This);

    if (info.Length() != 3) {
      THROW_ERROR("ecdsa_verify called with wrong number of arguments");
    }

    GET_ECDSA_SIGNATURE(signature, info[0]);
    
    GET_MESSAGE(message, info[1]);

    GET_PUBKEY(pubkey, info[2]);

    RETURN_BOOLEAN(1 == secp256k1_ecdsa_verify(This->ctx, &signature, message, &pubkey));
  }

  static NAN_METHOD(ecdsa_sign) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("ecdsa_sign called with wrong number of arguments");
    }

    GET_MESSAGE(message, info[0]);

    GET_SECRETKEY(seckey, info[1]);

    secp256k1_ecdsa_signature signature;

    if (!secp256k1_ecdsa_sign(This->ctx, &signature, message, seckey, (secp256k1_nonce_function)secp256k1_nonce_function_rfc6979, NULL)) {
      THROW_ERROR("secp256k1_ecdsa_sign failed");
    }

    RETURN_ECDSA_SIGNATURE(signature);
  }

  static NAN_METHOD(ec_seckey_verify) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("ec_seckey_verify called with wrong number of arguments");
    }

    GET_SECRETKEY(secret_key, info[0]);

    RETURN_BOOLEAN(1 == secp256k1_ec_seckey_verify(This->ctx, secret_key));
  }

  static NAN_METHOD(ec_pubkey_create) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("ec_pubkey_create called with wrong number of arguments");
    }

    GET_SECRETKEY(secretkey, info[0]);

    secp256k1_pubkey pubkey;
    
    if (!secp256k1_ec_pubkey_create(This->ctx, &pubkey, secretkey)) {
      THROW_ERROR("secp256k1_ec_pubkey_create failed");
    }

    RETURN_PUBKEY(pubkey);
  }

  static NAN_METHOD(ec_privkey_tweak_add) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("ec_privkey_tweak_add called with wrong number of arguments");
    }

    GET_SECRETKEY(secretkey, info[0]);

    GET_SECRETKEY(tweak, info[1]);

    if (!secp256k1_ec_privkey_tweak_add(This->ctx, secretkey, tweak)) {
      THROW_ERROR("secp256k1_ec_privkey_tweak_add failed");
    }

    RETURN_SECRETKEY(secretkey);
  }

  static NAN_METHOD(ec_pubkey_tweak_add) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("ec_pubkey_tweak_add called with wrong number of arguments");
    }

    GET_PUBKEY(pubkey, info[0]);

    GET_SECRETKEY(tweak, info[1]);

    if (!secp256k1_ec_pubkey_tweak_add(This->ctx, &pubkey, tweak)) {
      THROW_ERROR("secp256k1_ec_pubkey_tweak_add failed");
    }

    RETURN_PUBKEY(pubkey);
  }

  static NAN_METHOD(ec_privkey_tweak_mul) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("ec_privkey_tweak_mul called with wrong number of arguments");
    }

    GET_SECRETKEY(secretkey, info[0]);

    GET_SECRETKEY(tweak, info[1]);

    if (!secp256k1_ec_privkey_tweak_add(This->ctx, secretkey, tweak)) {
      THROW_ERROR("secp256k1_ec_privkey_tweak_mul failed");
    }

    RETURN_SECRETKEY(secretkey);
  }

  static NAN_METHOD(ec_pubkey_tweak_mul) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("ec_pubkey_tweak_mul called with wrong number of arguments");
    }

    GET_PUBKEY(pubkey, info[0]);

    GET_SECRETKEY(tweak, info[1]);

    if (!secp256k1_ec_pubkey_tweak_add(This->ctx, &pubkey, tweak)) {
      THROW_ERROR("secp256k1_ec_pubkey_tweak_mul failed");
    }

    RETURN_PUBKEY(pubkey);
  }

  static NAN_METHOD(context_randomize) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("context_randomize called with wrong number of arguments");
    }

    GET_SEED(seed, info[0]);

    if (!secp256k1_context_randomize(This->ctx, seed)) {
      THROW_ERROR("secp256k1_context_randomize failed");
    }

    RETURN_BOOLEAN(true);
  }

  static NAN_METHOD(pedersen_commitment_parse) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("pedersen_commitment_parse called with wrong number of arguments");
    }

    GET_BUFFER_LENGTH(buffer, info[0], 33, "buffer needs to be a Buffer of length 33");

    secp256k1_pedersen_commitment commitment = { .data = { 0x0 } };

    if (!secp256k1_pedersen_commitment_parse(This->ctx, &commitment, buffer)) {
      THROW_ERROR("secp256k1_pedersen_commitment_parse failed");
    }

    RETURN_COMMITMENT(commitment);
  }

  static NAN_METHOD(pedersen_commitment_serialize) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("pedersen_commitment_serialize called with wrong number of arguments");
    }

    GET_COMMITMENT(commitment, info[0]);

    unsigned char commitment_serialized[33] = { 0 };
    if (!secp256k1_pedersen_commitment_serialize(This->ctx, commitment_serialized, &commitment)) {
      THROW_ERROR("secp256k1_pedersen_commitment_serialize failed");
    }

    RETURN_BUFFER(commitment_serialized, 33);
  }

  static NAN_METHOD(pedersen_commit) {
    GET_HOLDER(This);

    if (info.Length() != 1 && info.Length() != 2) {
      THROW_ERROR("pedersen_commit called with wrong number of arguments");
    }

    GET_UINT64_T(value, info[0]);

    unsigned char blind[32] = {0};

    if (info.Length() == 2) {
      GET_SECRETKEY(blindarg, info[1]);
      memcpy(blind, blindarg, 32);
    }

    secp256k1_pedersen_commitment commitment = { .data = { 0x0 } };

    if (!secp256k1_pedersen_commit(This->ctx, &commitment, blind, value, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
      THROW_ERROR("secp256k1_pedersen_commit failed");
    }

    RETURN_COMMITMENT(commitment);
  }

  static NAN_METHOD(pedersen_blind_switch) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("pedersen_blind_switch called with wrong number of arguments");
    }

    GET_UINT64_T(value, info[0]);

    unsigned char blind[32] = {0};

    if (info.Length() == 2) {
      GET_SECRETKEY(blindarg, info[1]);
      memcpy(blind, blindarg, 32);
    }

    unsigned char blind_switch[32] = {0};

    if (!secp256k1_blind_switch(This->ctx, blind_switch, blind, value, &secp256k1_generator_const_h, &secp256k1_generator_const_g, &GENERATOR_J_PUB)) {
      THROW_ERROR("secp256k1_pedersen_commit failed");
    }

    RETURN_BLIND(blind_switch);
  }

  static NAN_METHOD(pedersen_blind_sum) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("pedersen_blind_sum called with wrong number of arguments");
    }
    
    GET_ARRAY(blinds, info[0], "blinds must be an Array of Buffers");
    
    GET_INTEGER(npositive, info[1], "npositive needs to be a number");

    if (npositive > blinds->Length()) {
      THROW_ERROR("npositive cannot be greater than the length of blinds");
    }

    unsigned char blind_list[blinds->Length()][32];
    unsigned char * blind_ptrs[blinds->Length()];

    for (unsigned int i = 0; i < blinds->Length(); ++i) {
      GET_BLIND_FROM_ARRAY(blind, blinds, i);
      memcpy(blind_list[i], blind, 32);
      blind_ptrs[i] = blind_list[i];
    }

    unsigned char blind_sum[32];

    if (!secp256k1_pedersen_blind_sum(This->ctx, blind_sum, blind_ptrs, blinds->Length(), (size_t)npositive)) {
      THROW_ERROR("secp256k1_pedersen_blind_sum failed");
    }

    RETURN_BLIND(blind_sum);
  }

  static NAN_METHOD(pedersen_commit_sum) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("pedersen_commit_sum called with wrong number of arguments");
    }

    GET_ARRAY(pcommits, info[0], "pcommits must be an Array of Buffers");

    GET_ARRAY(ncommits, info[1], "ncommits must be an Array of Buffers");

    secp256k1_pedersen_commitment pcommitments[pcommits->Length()];
    secp256k1_pedersen_commitment ncommitments[ncommits->Length()];

    secp256k1_pedersen_commitment *pptrs[pcommits->Length()];
    secp256k1_pedersen_commitment *nptrs[ncommits->Length()];

    for (unsigned int i = 0; i < pcommits->Length(); ++i) {
      GET_COMMITMENT_FROM_ARRAY(commitment, pcommits, i);
      memcpy(pcommitments[i].data, commitment.data, 64);
      pptrs[i] = &pcommitments[i];
    }

    for (unsigned int i = 0; i < ncommits->Length(); ++i) {
      GET_COMMITMENT_FROM_ARRAY(commitment, ncommits, i);
      memcpy(ncommitments[i].data, commitment.data, 64);
      nptrs[i] = &ncommitments[i];
    }

    secp256k1_pedersen_commitment commitment_sum = { .data = { 0x0 } };

    if (!secp256k1_pedersen_commit_sum(This->ctx, &commitment_sum, pptrs, pcommits->Length(), nptrs, ncommits->Length())) {
      THROW_ERROR("secp256k1_pedersen_commit_sum failed");
    }

    RETURN_COMMITMENT(commitment_sum);
  }

  static NAN_METHOD(pedersen_verify_tally) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("pedersen_verify_tally called with wrong number of arguments");
    }

    GET_ARRAY(pcommits, info[0], "pcommits must be an Array of Buffers");

    GET_ARRAY(ncommits, info[1], "ncommits must be an Array of Buffers");

    secp256k1_pedersen_commitment pcommitments[pcommits->Length()];
    secp256k1_pedersen_commitment ncommitments[ncommits->Length()];

    secp256k1_pedersen_commitment *pptrs[pcommits->Length()];
    secp256k1_pedersen_commitment *nptrs[ncommits->Length()];

    for (unsigned int i = 0; i < pcommits->Length(); ++i) {
      GET_COMMITMENT_FROM_ARRAY(commitment, pcommits, i);
      memcpy(pcommitments[i].data, commitment.data, 64);
      pptrs[i] = &pcommitments[i];
    }

    for (unsigned int i = 0; i < ncommits->Length(); ++i) {
      GET_COMMITMENT_FROM_ARRAY(commitment, ncommits, i);
      memcpy(ncommitments[i].data, commitment.data, 64);
      nptrs[i] = &ncommitments[i];
    }

    RETURN_BOOLEAN(1 == secp256k1_pedersen_verify_tally(This->ctx, pptrs, pcommits->Length(), nptrs, ncommits->Length()));
  }

  static NAN_METHOD(pedersen_commitment_to_pubkey) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("pedersen_commitment_to_pubkey called with wrong number of arguments");
    }

    GET_COMMITMENT(commitment, info[0]);

    secp256k1_pubkey pubkey;
    if (!secp256k1_pedersen_commitment_to_pubkey(This->ctx, &pubkey, &commitment)) {
      THROW_ERROR("secp256k1_pedersen_commitment_to_pubkey failed");
    }

    RETURN_PUBKEY(pubkey);
  }

  static NAN_METHOD(aggsig_export_secnonce_single) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("aggsig_export_secnonce_single called with wrong number of arguments");
    }

    GET_SEED(seed, info[0]);
    
    unsigned char secretkey[32];
    if (!secp256k1_aggsig_export_secnonce_single(This->ctx, secretkey, seed)) {
      THROW_ERROR("secp256k1_aggsig_export_secnonce_single failed");
    }

    RETURN_SECRETKEY(secretkey);
  }

  static NAN_METHOD(aggsig_sign_single) {
    GET_HOLDER(This);

    if (info.Length() != 8) {
      THROW_ERROR("aggsig_sign_single called with wrong number of arguments");
    }
    
    GET_MESSAGE(message, info[0]);

    GET_SECRETKEY(seckey, info[1]);
    
    GET_SECRETKEY_NULL(secnonce, info[2]);

    GET_SECRETKEY_NULL(extra, info[3]);

    GET_PUBKEY_NULL(pubnonce, info[4]);

    GET_PUBKEY_NULL(pubnonce_total, info[5]);

    GET_PUBKEY_NULL(pubkey_for_e, info[6]);

    GET_SEED(seed, info[7]);

    unsigned char signature[64];
    if (!secp256k1_aggsig_sign_single(This->ctx, signature, message, seckey, secnonce, extra, pubnonce, pubnonce_total, pubkey_for_e, seed)) {
      THROW_ERROR("secp256k1_aggsig_sign_single failed");
    }

    RETURN_SIGNATURE(signature);
  }

  static NAN_METHOD(aggsig_add_signatures_single) {
    GET_HOLDER(This);

    if (info.Length() != 2) {
      THROW_ERROR("aggsig_add_signatures_single called with wrong number of arguments");
    }

    GET_ARRAY(signatures, info[0], "signatures must be an Array of Buffers");
    
    GET_PUBKEY(pubnonce_total, info[1]);

    unsigned char sigs[signatures->Length()][64];
    const unsigned char *ptrs[signatures->Length()];
    for (unsigned int i = 0; i < signatures->Length(); ++i) {
      GET_SIGNATURE_FROM_ARRAY(signature, signatures, i);
      memcpy(sigs[i], signature, 64);
      ptrs[i] = sigs[i];
    }

    unsigned char signature[64];
    if (!secp256k1_aggsig_add_signatures_single(This->ctx, signature, ptrs, signatures->Length(), &pubnonce_total)) {
      THROW_ERROR("secp256k1_aggsig_add_signatures_single failed");
    }

    RETURN_SIGNATURE(signature);
  }

  static NAN_METHOD(aggsig_verify_single) {
    GET_HOLDER(This);

    if (info.Length() != 7) {
      THROW_ERROR("aggsig_verify_single called with wrong number of arguments");
    }

    GET_SIGNATURE(signature, info[0]);

    GET_MESSAGE(message, info[1]);

    GET_PUBKEY_NULL(pubnonce, info[2]);

    GET_PUBKEY(pubkey, info[3]);

    GET_PUBKEY_NULL(pubkey_total, info[4]);

    GET_PUBKEY_NULL(extra_pubkey, info[5]);

    int is_partial = info[6]->IsTrue() ? 1 : 0;

    RETURN_BOOLEAN(1 == secp256k1_aggsig_verify_single(This->ctx, signature, message, pubnonce, &pubkey, pubkey_total, extra_pubkey, is_partial));
  }

  static NAN_METHOD(aggsig_verify) {
    GET_HOLDER(This);

    if (info.Length() != 3) {
      THROW_ERROR("aggsig_verify called with wrong number of arguments");
    }

    GET_SIGNATURE(signature, info[0]);

    GET_MESSAGE(message, info[1]);

    GET_ARRAY(pubkeys, info[2], "pubkeys must be an Array of Buffers");

    secp256k1_pubkey keys[pubkeys->Length()];
    secp256k1_pubkey *ptrs[pubkeys->Length()];
    for (unsigned int i = 0; i < pubkeys->Length(); ++i) {
      GET_PUBKEY_FROM_ARRAY(pubkey, pubkeys, i);
      memcpy(keys[i].data, pubkey.data, 64);
      ptrs[i] = &keys[i];
    }

    RETURN_BOOLEAN(1 == secp256k1_aggsig_build_scratch_and_verify(This->ctx, signature, message, keys, pubkeys->Length()));
  }

  static NAN_METHOD(bulletproof_rangeproof_verify) {
    GET_HOLDER(This);

    if (info.Length() != 3) {
      THROW_ERROR("bulletproof_rangeproof_verify called with wrong number of arguments");
    }

    GET_BUFFER(rangeproof, info[0], "rangeproof needs to be a Buffer");

    GET_COMMITMENT(commitment, info[1]);

    GET_BUFFER_NULL(extra_data, info[2], "extra_data must be a Buffer or null");
    
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(This->ctx, SCRATCH_SPACE_SIZE);
    int result = secp256k1_bulletproof_rangeproof_verify(This->ctx, scratch, This->bulletproof_generators, rangeproof, rangeproof_length, NULL, &commitment, 1, 64, &secp256k1_generator_const_h, extra_data, extra_data_length);
    secp256k1_scratch_space_destroy(scratch);
    RETURN_BOOLEAN(1 == result);
  }

  static NAN_METHOD(bulletproof_rangeproof_verify_multi) {
    GET_HOLDER(This);

    if (info.Length() != 3) {
      THROW_ERROR("bulletproof_rangeproof_verify_multi called with wrong number of arguments");
    }

    GET_ARRAY(proofs, info[0], "proofs must be an Array of Buffers");

    GET_ARRAY(commits, info[1], "commits must be an Array of Buffers");

    GET_ARRAY_NULL(extra_data, info[2], "extra_data must be an Array of Buffers or null");

    size_t plen = SINGLE_BULLET_PROOF_SIZE;

    if (proofs->Length() != commits->Length()) {
      THROW_ERROR("proofs and commits should be same length Arrays");
    }

    if (!extra_data->IsNullOrUndefined() && extra_data->Length() != proofs->Length()) {
      THROW_ERROR("extra_data needs to be null or the same length as proofs");
    }

    size_t length = proofs->Length();

    if (length > 0) {
      GET_BUFFER_FROM_ARRAY(proof, proofs, 1, "proofs must be an Array of Buffers");
      plen = proof_length;
    }
    
    unsigned char rangeproofs[length][plen];
    unsigned char *rangeproofptrs[length];
    secp256k1_pedersen_commitment commitments[length];
    secp256k1_pedersen_commitment *commitmentptrs[length];
    unsigned char *extradataptrs[length];
    size_t extradatalens[length];
    
    for (size_t i = 0; i < length; ++i) {
      GET_BUFFER_FROM_ARRAY(proof, proofs, i, "proofs must be an Array of Buffers");
      if (proof_length != plen) {
        THROW_ERROR("Each proof element in proofs must be of the same length");
      }
      memcpy(rangeproofs[i], proof, plen);
      rangeproofptrs[i] = rangeproofs[i];

      GET_COMMITMENT_FROM_ARRAY(commitment, commits, i);
      memcpy(commitments[i].data, commitment.data, 64);
      commitmentptrs[i] = &commitments[i];

      if (!extra_data->IsNullOrUndefined()) {
        GET_BUFFER_PTR_FROM_ARRAY(extra, extra_data, i, "extra_data must be an Array of Buffers");
        extradataptrs[i] = extra;
        extradatalens[i] = extra_length;
      } else {
        extradataptrs[i] = NULL;
        extradatalens[i] = 0;
      }
    }
    
    size_t num_generators = std::max<size_t>(proofs->Length(), size_t(1));
    secp256k1_generator value_gen[num_generators];
    
    for (unsigned int i = 0; i < num_generators; ++i) {
      memcpy(value_gen[i].data, secp256k1_generator_const_h.data, 64);
    }

    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(This->ctx, SCRATCH_SPACE_SIZE);
    int result = secp256k1_bulletproof_rangeproof_verify_multi(This->ctx, scratch, This->bulletproof_generators, rangeproofptrs, length, plen, NULL, commitmentptrs, 1, 64, &value_gen[0], extradataptrs, extradatalens);

    secp256k1_scratch_space_destroy(scratch);
    RETURN_BOOLEAN(1 == result);
  }

  static NAN_METHOD(bulletproof_rangeproof_rewind) {
    GET_HOLDER(This);

    if (info.Length() != 4) {
      THROW_ERROR("bulletproof_rangeproof_rewind called with wrong number of arguments");
    }

    GET_BUFFER(proof, info[0], "proof needs to be a Buffer");

    GET_COMMITMENT(commitment, info[1]);

    GET_SECRETKEY(nonce, info[2]);

    GET_BUFFER_NULL(extra_data, info[3], "extra_data must be an Array of Buffers or null");

    uint64_t value;
    unsigned char blind[32];
    unsigned char message[16] = { 0 };

    if (!secp256k1_bulletproof_rangeproof_rewind(This->ctx, This->bulletproof_generators, &value, blind, proof, proof_length, 0, &commitment, &secp256k1_generator_const_h, nonce, extra_data, extra_data_length, message)) {
      THROW_ERROR("secp256k1_bulletproof_rangeproof_rewind call failed");
    }

    v8::Local<v8::Object> result = Nan::New<v8::Object>();
    v8::Local<v8::String> valueProp = Nan::New("value").ToLocalChecked();
    v8::Local<v8::String> blindProp = Nan::New("blind").ToLocalChecked();
    v8::Local<v8::String> messageProp = Nan::New("message").ToLocalChecked();
    Nan::Set(result, valueProp, Nan::New<v8::Number>(value));
    Nan::Set(result, blindProp, COPY_BUFFER(blind, 32));
    Nan::Set(result, messageProp, COPY_BUFFER(message, 16));

    RETURN_OBJECT(result);
  }

  static NAN_METHOD(bulletproof_rangeproof_prove) {
    GET_HOLDER(This);

    if (info.Length() != 5) {
      THROW_ERROR("bulletproof_rangeproof_prove called with wrong number of arguments");
    }

    GET_UINT64_T(value, info[0]);

    GET_SECRETKEY(blind, info[1]);

    GET_SECRETKEY(nonce, info[2]);

    GET_BUFFER_NULL(extra_data, info[3], "extra_data must be a Buffer or null");

    GET_BUFFER_LENGTH_NULL(message, info[4], 16, "message must be a Buffer of length 16 or null");

    unsigned char *blindptrs[1] = { blind };
    size_t plen = SINGLE_BULLET_PROOF_SIZE;
    unsigned char proof[plen];
  
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(This->ctx, SCRATCH_SPACE_SIZE);
    if(!secp256k1_bulletproof_rangeproof_prove(
      This->ctx, 
      scratch, 
      This->bulletproof_generators, 
      proof, 
      &plen, 
      NULL, // tau_x 
      NULL, // t_one
      NULL, // t_two
      &value, 
      NULL, // min_values
      blindptrs, 
      NULL, // commits
      1, 
      &secp256k1_generator_const_h, 
      64,  // nbits
      nonce, 
      NULL, // private_nonce
      extra_data, 
      extra_data_length, 
      message)
    ) {
      secp256k1_scratch_space_destroy(scratch);
      THROW_ERROR("secp256k1_bulletproof_rangeproof_prove call failed");
    }
    secp256k1_scratch_space_destroy(scratch);

    RETURN_BUFFER(proof, plen);
  }

  static NAN_METHOD(ec_pubkey_combine) {
    GET_HOLDER(This);

    if (info.Length() != 1) {
      THROW_ERROR("ec_pubkey_combine called with wrong number of arguments");
    }

    GET_ARRAY(pubkeys, info[0], "pubkeys must be an Array of Buffers");

    secp256k1_pubkey keys[pubkeys->Length()];
    secp256k1_pubkey *ptrs[pubkeys->Length()];
    for (unsigned int i = 0; i < pubkeys->Length(); ++i) {
      GET_PUBKEY_FROM_ARRAY(pubkey, pubkeys, i);
      memcpy(keys[i].data, pubkey.data, 64);
      ptrs[i] = &keys[i];
    }

    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_combine(This->ctx, &pubkey, ptrs, pubkeys->Length())) {
      THROW_ERROR("secp256k1_bulletproof_rangeproof_prove call failed");
    }

    RETURN_PUBKEY(pubkey);
  }

 public:

  secp256k1_context *ctx;
  secp256k1_bulletproof_generators *bulletproof_generators;

  static NAN_MODULE_INIT(Init) {
    v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(New);
    constructor.Reset(ctor);
    ctor->SetClassName(Nan::New("Secp256k1zkp").ToLocalChecked());
    ctor->InstanceTemplate()->SetInternalFieldCount(1);
    
    ADD_METHOD(ec_pubkey_parse);
    ADD_METHOD(ec_pubkey_serialize);
    ADD_METHOD(ecdsa_signature_parse_compact);
    ADD_METHOD(ecdsa_signature_parse_der);
    ADD_METHOD(ecdsa_signature_serialize_compact);
    ADD_METHOD(ecdsa_verify);
    ADD_METHOD(ecdsa_sign);
    ADD_METHOD(ec_pubkey_create);
    ADD_METHOD(ec_seckey_verify);
    ADD_METHOD(ec_privkey_tweak_add);
    ADD_METHOD(ec_pubkey_tweak_add);
    ADD_METHOD(context_randomize);
    ADD_METHOD(pedersen_commitment_parse);
    ADD_METHOD(pedersen_commitment_serialize);
    ADD_METHOD(pedersen_commit);
    ADD_METHOD(pedersen_blind_switch);
    ADD_METHOD(pedersen_blind_sum);
    ADD_METHOD(pedersen_commit_sum);
    ADD_METHOD(pedersen_verify_tally);
    ADD_METHOD(pedersen_commitment_to_pubkey);
    ADD_METHOD(aggsig_export_secnonce_single);
    ADD_METHOD(aggsig_sign_single);
    ADD_METHOD(aggsig_add_signatures_single);
    ADD_METHOD(aggsig_verify_single);
    ADD_METHOD(aggsig_verify);
    ADD_METHOD(bulletproof_rangeproof_verify);
    ADD_METHOD(bulletproof_rangeproof_verify_multi);
    ADD_METHOD(bulletproof_rangeproof_rewind);
    ADD_METHOD(bulletproof_rangeproof_prove);
    ADD_METHOD(ec_pubkey_combine);

    target->Set(Nan::New("Secp256k1zkp").ToLocalChecked(), ctor->GetFunction());
  }
};

Nan::Persistent<v8::FunctionTemplate> Secp256k1zkp::constructor;

NAN_MODULE_INIT(InitModule) {
  Secp256k1zkp::Init(target);
}

NODE_MODULE(secp256k1zkp, InitModule);