#ifndef __SECP256K1ZKP_ERRORS__
#define __SECP256K1ZKP_ERRORS__

#include <string.h>
#include <nan.h>
#include <node.h>

#define THROW_ERROR(message) return Nan::ThrowError(Nan::New(message).ToLocalChecked())

#define CHECK_TYPE_OBJECT(value, message) { \
  if (!value->IsObject()) {                 \
    return Nan::ThrowTypeError(message);    \
  }                                         \
}

#define CHECK_TYPE_ARRAY(value, message) { \
  if (!value->IsArray()) {                 \
    return Nan::ThrowTypeError(message);   \
  }                                        \
}

#define CHECK_TYPE_ARRAY_NULL(value, message) {           \
  if (!value->IsNullOrUndefined() && !value->IsArray()) { \
    return Nan::ThrowTypeError(message);                  \
  }                                                       \
}

#define CHECK_TYPE_BUFFER(value, message) { \
  if (!node::Buffer::HasInstance(value)) {  \
    return Nan::ThrowTypeError(message);    \
  }                                         \
}

#define CHECK_TYPE_BUFFER_LENGTH(value, length, message) {                          \
  if (!node::Buffer::HasInstance(value) || node::Buffer::Length(value) != length) { \
    return Nan::ThrowTypeError(message);                                            \
  }                                                                                 \
}

#define CHECK_TYPE_NUMBER(value, message) {             \
  if (!value->IsNumber() && !value->IsNumberObject()) { \
    return Nan::ThrowTypeError(message);                \
  }                                                     \
}

#define COPY_BUFFER(data, datalen) Nan::CopyBuffer((const char *)data, (uint32_t)datalen).ToLocalChecked()

#define GET_HOLDER(variable) \
  Secp256k1zkp *variable = ObjectWrap::Unwrap<Secp256k1zkp>(info.Holder());

#define ADD_METHOD(method) Nan::SetPrototypeMethod(ctor, #method, method);

#if NODE_MODULE_VERSION > NODE_8_0_MODULE_VERSION
#define INTEGER_VALUE(obj) obj.As<v8::Integer>()->Value()
#else
#define INTEGER_VALUE(obj) obj.As(v8::Integer>(->IntegerValue()
#endif

#define GET_INTEGER(variable, value, message)                    \
  v8::Local<v8::Object> variable##_obj = value.As<v8::Object>(); \
  CHECK_TYPE_NUMBER(variable##_obj, message);                    \
  int64_t variable = INTEGER_VALUE(variable##_obj);

#define GET_BUFFER_LENGTH(variable, value, length, message)      \
  v8::Local<v8::Object> variable##_obj = value.As<v8::Object>(); \
  CHECK_TYPE_BUFFER_LENGTH(variable##_obj, length, message);     \
  unsigned char variable[length];                                \
  memcpy(&variable[0], node::Buffer::Data(variable##_obj), length);

#define GET_BUFFER_LENGTH_NULL(variable, value, length, message)             \
  unsigned char *variable = NULL;                                            \
  unsigned char variable##_data[length];                                     \
  if (!value->IsNullOrUndefined()) {                                         \
    v8::Local<v8::Object> variable##_obj = value.As<v8::Object>();           \
    CHECK_TYPE_BUFFER_LENGTH(variable##_obj, length, message);               \
    memcpy(&variable##_data[0], node::Buffer::Data(variable##_obj), length); \
    variable = variable##_data;                                              \
  }

#define GET_BUFFER(variable, value, message)                       \
  v8::Local<v8::Object> variable##_obj = value.As<v8::Object>();   \
  CHECK_TYPE_BUFFER(variable##_obj, message);                      \
  size_t variable##_length = node::Buffer::Length(variable##_obj); \
  unsigned char variable[variable##_length];                       \
  memcpy(&variable[0], node::Buffer::Data(variable##_obj), variable##_length);

#define GET_BUFFER_NULL(variable, value, message)                                       \
  size_t variable##_length = 0;                                                         \
  if (!value->IsNullOrUndefined()) {                                                    \
    v8::Local<v8::Object> variable##_obj = value.As<v8::Object>();                      \
    CHECK_TYPE_BUFFER(variable##_obj, message);                                         \
    variable##_length = node::Buffer::Length(variable##_obj);                           \
  }                                                                                     \
  unsigned char *variable = NULL;                                                       \
  unsigned char variable##_data[variable##_length];                                     \
  if (!value->IsNullOrUndefined()) {                                                    \
    v8::Local<v8::Object> variable##_obj = value.As<v8::Object>();                      \
    memcpy(&variable##_data[0], node::Buffer::Data(variable##_obj), variable##_length); \
    variable = variable##_data;                                                         \
  }

#define GET_ARRAY(variable, value, message)              \
  v8::Local<v8::Array> variable = value.As<v8::Array>(); \
  CHECK_TYPE_ARRAY(variable, message);

#define GET_ARRAY_NULL(variable, value, message)         \
  v8::Local<v8::Array> variable = value.As<v8::Array>(); \
  CHECK_TYPE_ARRAY_NULL(variable, message);

#define GET_ARRAY_FROM_ARRAY(element, array, index)                            \
  CHECK_TYPE_ARRAY(array->Get(index), #array " elements need to be an Array"); \
  v8::Local<v8::Array> element = v8::Local<v8::Array>::Cast(array->Get(index));

#define GET_BUFFER_FROM_ARRAY(buffer, array, index, message)                           \
  v8::Local<v8::Object> buffer##_obj = v8::Local<v8::Object>::Cast(array->Get(index)); \
  CHECK_TYPE_BUFFER(buffer##_obj, message);                                            \
  size_t buffer##_length = node::Buffer::Length(buffer##_obj);                         \
  unsigned char buffer[buffer##_length];                                               \
  memcpy(&buffer[0], node::Buffer::Data(buffer##_obj), buffer##_length);

#define GET_BUFFER_PTR_FROM_ARRAY(buffer, array, index, message)                       \
  v8::Local<v8::Object> buffer##_obj = v8::Local<v8::Object>::Cast(array->Get(index)); \
  CHECK_TYPE_BUFFER(buffer##_obj, message);                                            \
  size_t buffer##_length = node::Buffer::Length(buffer##_obj);                         \
  unsigned char *buffer = (unsigned char *)node::Buffer::Data(buffer##_obj);           

#define GET_BLIND_FROM_ARRAY(blind, array, index)                                                 \
  v8::Local<v8::Object> blind##_obj = v8::Local<v8::Object>::Cast(array->Get(index));             \
  CHECK_TYPE_BUFFER_LENGTH(blind##_obj, 32, #array " elements need to be a Buffer of length 32"); \
  unsigned char blind[32];                                                                        \
  memcpy(&blind[0], node::Buffer::Data(blind##_obj), 32);

#define GET_SIGNATURE_FROM_ARRAY(signature, array, index)                                             \
  v8::Local<v8::Object> signature##_obj = v8::Local<v8::Object>::Cast(array->Get(index));             \
  CHECK_TYPE_BUFFER_LENGTH(signature##_obj, 64, #array " elements need to be a Buffer of length 64"); \
  unsigned char signature[64];                                                                        \
  memcpy(&signature[0], node::Buffer::Data(signature##_obj), 64);

#define GET_COMMITMENT_FROM_ARRAY(commitment, array, index)                                            \
  v8::Local<v8::Object> commitment##_obj = v8::Local<v8::Object>::Cast(array->Get(index));             \
  CHECK_TYPE_BUFFER_LENGTH(commitment##_obj, 64, #array " elements need to be a Buffer of length 64"); \
  secp256k1_pedersen_commitment commitment;                                                            \
  memcpy(commitment.data, node::Buffer::Data(commitment##_obj), 64);

#define GET_PUBKEY_FROM_ARRAY(pubkey, array, index)                                                \
  v8::Local<v8::Object> pubkey##_obj = v8::Local<v8::Object>::Cast(array->Get(index));             \
  CHECK_TYPE_BUFFER_LENGTH(pubkey##_obj, 64, #array " elements need to be a Buffer of length 64"); \
  secp256k1_pubkey pubkey;                                                                         \
  memcpy(pubkey.data, node::Buffer::Data(pubkey##_obj), 64);

#define GET_COMMITMENT(variable, argument)                                                          \
  GET_BUFFER_LENGTH(variable##_data, argument, 64, #variable " needs to be a Buffer of length 64"); \
  secp256k1_pedersen_commitment variable;                                                           \
  memcpy(variable.data, variable##_data, 64)

#define GET_MESSAGE(variable, argument) \
  GET_BUFFER_LENGTH(variable, argument, 32, #variable " needs to be a Buffer of length 32")

#define GET_SEED(variable, argument) \
  GET_BUFFER_LENGTH(variable, argument, 32, #variable " needs to be a Buffer of length 32")

#define GET_SECRETKEY(variable, argument) \
  GET_BUFFER_LENGTH(variable, argument, 32, #variable " needs to be a Buffer of length 32")

#define GET_SECRETKEY_NULL(variable, argument) \
  GET_BUFFER_LENGTH_NULL(variable, argument, 32, #variable " needs to be a Buffer of length 32")

#define GET_SIGNATURE(variable, argument) \
  GET_BUFFER_LENGTH(variable, argument, 64, #variable " needs to be a Buffer of length 32")

#define GET_PUBKEY(variable, argument)                                                              \
  GET_BUFFER_LENGTH(variable##_data, argument, 64, #variable " needs to be a Buffer of length 64"); \
  secp256k1_pubkey variable;                                                                        \
  memcpy(variable.data, variable##_data, 64)

#define GET_PUBKEY_NULL(variable, argument)                                                              \
  secp256k1_pubkey *variable = NULL;                                                                     \
  secp256k1_pubkey variable##_obj;                                                                       \
  GET_BUFFER_LENGTH_NULL(variable##_data, argument, 64, #variable " needs to be a Buffer of length 64"); \
  if (variable##_data != NULL) {                                                                         \
    memcpy(variable##_obj.data, variable##_data, 64);                                                    \
    variable = &variable##_obj;                                                                           \
  }

#define GET_ECDSA_SIGNATURE(variable, argument)                                                     \
  GET_BUFFER_LENGTH(variable##_data, argument, 64, #variable " needs to be a Buffer of length 64"); \
  secp256k1_ecdsa_signature variable;                                                               \
  memcpy(variable.data, variable##_data, 64)

#define BYTES_TO_UINT64_T(b) \
  ((uint64_t)b[7] << 0) | ((uint64_t)b[6] << 8) | ((uint64_t)b[5] << 16) | ((uint64_t)b[4] << 24) | ((uint64_t)b[3] << 32) | ((uint64_t)b[2] << 40) | ((uint64_t)b[1] << 48) | ((uint64_t)b[0] << 56)

#define GET_UINT64_T(variable, argument)                                                                                \
  GET_BUFFER_LENGTH(variable##_data, argument, 8, #variable " needs to be a uint64_t encoded as a big endian Buffer"); \
  uint64_t variable = BYTES_TO_UINT64_T(variable##_data)

#define RETURN_THIS() info.GetReturnValue().Set(info.Holder())

#define RETURN_BOOLEAN(value) info.GetReturnValue().Set(Nan::New<v8::Boolean>(value))

#define RETURN_BUFFER(buffer, len) info.GetReturnValue().Set(COPY_BUFFER(buffer, len))

#define RETURN_COMMITMENT(commitment) RETURN_BUFFER(commitment.data, 64)

#define RETURN_SECRETKEY(key) RETURN_BUFFER(key, 32)

#define RETURN_PUBKEY(key) RETURN_BUFFER(key.data, 64)

#define RETURN_SIGNATURE(signature) RETURN_BUFFER(signature, 64)

#define RETURN_ECDSA_SIGNATURE(signature) RETURN_BUFFER(signature.data, 64)

#define RETURN_BLIND(blind) RETURN_BUFFER(blind, 32)

#define RETURN_OBJECT(obj) info.GetReturnValue().Set(obj)

#endif