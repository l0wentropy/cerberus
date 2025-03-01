#ifndef __UTILS_HPP
#define __UTILS_HPP

#include <stdio.h>
#include <stdlib.h>
#include <iomanip>
#include <cstdio>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <vector>
#include <iostream>
#include <sstream>

//#define __DEBUG_ENABLED
#ifdef __DEBUG_ENABLED
#define LOGGING_LEVEL_3
#include "../../common/logging.hpp"
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <argon2.h>

#define SHA256_DIGEST_LENGTH 32
#define SHA512_DIGEST_LENGTH 64

#define DEFAULT_RSA_KEY_SIZE 8192

#define AES256_KEY_SIZE 32
#define IV_SIZE         12
#define TAG_SIZE        16

#define GCM_PROCESS_CHUNK_SIZE  1024 * 8

#define PBKDF2_ITERATIONS 1024 * 1024 * 32

const unsigned char AAD_DATA[] = {
  0x30, 0x37, 0x44, 0x34, 0x35, 0x34, 0x31, 0x30, 0x45, 0x36, 0x43, 0x30,
  0x38, 0x45, 0x39, 0x41, 0x30, 0x38, 0x41, 0x44, 0x38, 0x34, 0x37, 0x38,
  0x30, 0x39, 0x44, 0x42, 0x42, 0x31, 0x45, 0x38, 0x39, 0x33, 0x41, 0x39,
  0x34, 0x30, 0x35, 0x38, 0x44, 0x45, 0x31, 0x33, 0x36, 0x43, 0x34, 0x43,
  0x34, 0x30, 0x42, 0x33, 0x32, 0x35, 0x35, 0x42, 0x35, 0x35, 0x35, 0x45,
  0x32, 0x46, 0x38, 0x38, 0x37, 0x30, 0x31, 0x41, 0x38, 0x41, 0x44, 0x36,
  0x34, 0x41, 0x35, 0x33, 0x35, 0x31, 0x38, 0x44, 0x32, 0x41, 0x39, 0x41,
  0x33, 0x33, 0x46, 0x34, 0x45, 0x43, 0x31, 0x36, 0x45, 0x46, 0x42, 0x34,
  0x32, 0x46, 0x33, 0x34, 0x30, 0x42, 0x44, 0x33, 0x38, 0x35, 0x36, 0x39,
  0x45, 0x46, 0x31, 0x35, 0x44, 0x33, 0x35, 0x37, 0x37, 0x39, 0x46, 0x31,
  0x42, 0x42, 0x45, 0x34, 0x35, 0x42, 0x31, 0x31
};
const unsigned int AAD_DATA_len = 128;

class utils
{
private:
  struct gcm_work_st
  {
    EVP_CIPHER_CTX *ctx;
    std::vector<unsigned char> vIv, vKey, vTag;
  };

public:
  utils();

  static bool IsFileExist(const std::string &filename);

  static bool ReadFile(
    const std::string &filename, std::vector<unsigned char> &vOut,
    const unsigned long long &ullLimit = 0, const unsigned long long &ullOffset = 0);

  static bool WriteFile(const std::string &filename, const std::vector<unsigned char> &vIn, const unsigned int &flags = 0);

  static int OpenFile(const std::string &filename, const mode_t &flags, long long &llRetSize);

  static bool SetSeekFileOffset(int &fd, const long long &llOffset);

  static ssize_t ReadFileChunk(int &fd, const long long &chunk, std::vector<unsigned char> &vOut);

  static ssize_t WriteFileChunk(int &fd, const std::vector<unsigned char> &vIn, const long long &chunk);

  static void CloseFile(int &fd);

  static unsigned long long GetFileSize(const std::string &filename);

  static bool Is32BitProcess();

  static void memset_sec(void *p, const unsigned long long &ullSize, bool &bIsZeroed);

  static std::string StringFromVector(const std::vector<unsigned char> &data);

  static std::vector<unsigned char> VectorFromString(const std::string &data);

  static std::vector<unsigned char> sha256(const std::vector<unsigned char> &input);

  static std::vector<unsigned char> sha512(const std::vector<unsigned char> &input);

  static std::vector<unsigned char> md5(const std::vector<unsigned char> &input);

  // Version 4 (random) / Variant 1 (10xx2)
  static bool gen_rand_uuid(std::vector<unsigned char> &vOut, const unsigned int &uiLen, const unsigned short &usLeft, const unsigned short &usRight);

  // 8-4-4-4-12
  static std::string bytes_to_uuid(const std::vector<unsigned char> &input);

  // FIXME: add version check by RFC
  static bool validate_uuid(const std::string &input);

  static std::string bytes_to_hex(const std::vector<unsigned char> &input);

  static unsigned int fillUnsignedInt(const std::vector<unsigned char> &vData);

  static unsigned long long fillUnsignedLongLong(const std::vector<unsigned char> &vData);

  static void divideUnsignedIntToShorts(const unsigned int &uiData, unsigned short &usLeft, unsigned short &usRight);

  static unsigned int combineShortsToUnsignedInt(const unsigned short &usLeft, const unsigned short &usRight);

  static std::string sToLower(const std::string &sIn);

  static bool genRandBytes(std::vector<unsigned char> &vOut, const unsigned int &uiLen);

  static int strCurveToNID(const std::string &sCurveName);

  static std::string NID2Str(const int &iNID);

  static EC_GROUP * ecGetGroup(const EC_KEY *ecKey);

  static int ecGetGroup(const EC_GROUP *ecGroup);

  static int ecGetECDHSize(const EC_KEY *ecKey);

  static int ecGetECDHSize(const EC_GROUP *ecGroup);

  static bool genKeyPairRSA(
    const std::string &sPathPublic,
    const std::string &sPathPrivate,
    const bool &bEnc = false,
    unsigned char* ucPwd = NULL,
    const unsigned int &uiPwdLen = 0);

  static bool genKeyPairEC(
    const std::string &sPathPublic,
    const std::string &sPathPrivate,
    const std::string &sCurveName,
    const bool &bEnc = false,
    unsigned char* ucPwd = NULL,
    const unsigned int &uiPwdLen = 0);

  static bool reencryptPrivRSA_PEM(
    const std::string &sPathIn,
    const std::string &sPathOut,
    unsigned char *ucOldPwd,
    const bool &bEnc = false,
    unsigned char *ucPwd = NULL,
    const unsigned int &uiPwdLen = 0);

  static bool reencryptPrivEC_PEM(
    const std::string &sPathIn,
    const std::string &sPathOut,
    unsigned char *ucOldPwd,
    const bool &bEnc = false,
    unsigned char *ucPwd = NULL,
    const unsigned int &uiPwdLen = 0);

  static RSA * getPubRSA(const std::string &sPath);

  static EC_KEY * getPubEC(const std::string &sPath);

  static RSA * getPrivRSA(const std::string &sPath, unsigned char *ucPwd = NULL);

  static EC_KEY * getPrivEC(const std::string &sPath, unsigned char *ucPwd = NULL);

  static RSA * getPubRSA(const std::vector<unsigned char> &vBuffer);

  static EC_KEY * getPubEC(const std::vector<unsigned char> &vBuffer);

  static RSA * getPrivRSA(const std::vector<unsigned char> &vBuffer, unsigned char *ucPwd = NULL);

  static EC_KEY * getPrivEC(const std::vector<unsigned char> &vBuffer, unsigned char *ucPwd = NULL);

  static int encryptRsa(const unsigned int &len, unsigned char *from, unsigned char *to, RSA *rsaKey);

  static int decryptRsa(const unsigned int &len, unsigned char *from, unsigned char *to, RSA *rsaKey);

  static bool ecPubToBin(const EC_KEY *ecKey, std::vector<unsigned char> &vOut);

  static bool ecPrivToBin(const EC_KEY *ecKey, std::vector<unsigned char> &vOut);

  static EC_POINT * ecPubBinToPoint(const std::vector<unsigned char> &vBuffer, const EC_GROUP *ecGroup);

  static bool eciesTXGenerateSymKey(const int &iCurve, const std::vector<unsigned char> &vPeerPubKey, std::vector<unsigned char> &vEPubKey, std::vector<unsigned char> &vSymKey);

  static bool eciesRXGenerateSymKey(const EC_KEY *ecKey, const std::vector<unsigned char> &vPeerPubKey, std::vector<unsigned char> &vSymKey);

  static int gcm_encrypt_in_place(
    unsigned char *plaintext, int plaintext_len,
    unsigned char *aad, int aad_len,
    unsigned char *key, int key_len,
    unsigned char *iv, int iv_len,
    unsigned char *ciphertext,
    unsigned char *tag);

  static int gcm_decrypt_in_place(
    unsigned char *ciphertext, int ciphertext_len,
    unsigned char *aad, int aad_len,
    unsigned char *tag,
    unsigned char *key, int key_len,
    unsigned char *iv, int iv_len,
    unsigned char *plaintext);

  static bool gcm_create_ctx_wrap(EVP_CIPHER_CTX **ctx);

  static bool gcm_encrypt_setup_wrap(
    EVP_CIPHER_CTX *ctx, unsigned char *aad, int aad_len,
    unsigned char *key, int key_len, unsigned char *iv, int iv_len);

  static bool gcm_decrypt_setup_wrap(
    EVP_CIPHER_CTX *ctx, unsigned char *aad, int aad_len,
    unsigned char *key, int key_len, unsigned char *iv, int iv_len);

  static bool gcm_encrypt_block_wrap(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int &out_len);

  static bool gcm_decrypt_block_wrap(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int &out_len);

  static bool gcm_encrypt_finalise_wrap(EVP_CIPHER_CTX *ctx, unsigned char *out, int &out_len);

  static bool gcm_decrypt_finalise_wrap(EVP_CIPHER_CTX *ctx, unsigned char *out, int &out_len);

  static bool gcm_get_tag_wrap(EVP_CIPHER_CTX *ctx, unsigned char *tag);

  static bool gcm_set_tag_wrap(EVP_CIPHER_CTX *ctx, unsigned char *tag);

  static void gcm_destroy_ctx_wrap(EVP_CIPHER_CTX **ctx);

  static bool gcm_setup_wrap(gcm_work_st *gcm_ctx, bool (*gcm_setup)(EVP_CIPHER_CTX*, unsigned char*, int, unsigned char*, int, unsigned char*, int));

  static bool gcmProcessFile(
    gcm_work_st *gcm_ctx, const std::string &sFileIn, const std::string &sFileOut,
    bool (*gcm_process)(EVP_CIPHER_CTX*, unsigned char*, int, unsigned char*, int&),
    unsigned long long &ullProcessedBytes, const long long &readTill = 0);

  static bool gcmEncryptFileWrap(
    const std::string &sIn, const std::string &sOut,
    const std::vector<unsigned char> &vKey, const std::vector<unsigned char> &vIv,
    unsigned long long &ullProcessedBytes, std::vector<unsigned char> &vTag);

  static bool gcmDecryptFileWrap(
    const std::string &sIn, const std::string &sOut,
    const std::vector<unsigned char> &vKey, const std::vector<unsigned char> &vIv,
    const std::vector<unsigned char> &vTag, const long long &llReadLimit,
    unsigned long long &ullProcessedBytes, const bool &bSkipVerify = false);

  static void PBKDF2_HMAC_SHA_512(unsigned char* pass, int passlen, unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, unsigned char* binResult);

  static bool argon2id(
    unsigned char* pass, uint32_t passlen, unsigned char* salt, uint32_t saltlen,
    uint32_t iterations, uint32_t memKibiBytes, uint32_t threads, uint32_t hashlen, unsigned char* hash,
    unsigned char* optSecret = NULL, uint32_t secretlen = 0);

  static bool argon2i(
    unsigned char* pass, uint32_t passlen, unsigned char* salt, uint32_t saltlen,
    uint32_t iterations, uint32_t memKibiBytes, uint32_t threads, uint32_t hashlen, unsigned char* hash,
    unsigned char* optSecret = NULL, uint32_t secretlen = 0);

  static bool argon2d(
    unsigned char* pass, uint32_t passlen, unsigned char* salt, uint32_t saltlen,
    uint32_t iterations, uint32_t memKibiBytes, uint32_t threads, uint32_t hashlen, unsigned char* hash,
    unsigned char* optSecret = NULL, uint32_t secretlen = 0);

  ~utils();
};

#endif

