#ifndef __CERBERUS_HPP
#define __CERBERUS_HPP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sstream>
#include <vector>

#include "utils.hpp"
#include "config.hpp"

#define _MAX_KEY_FILE_SIZE              1024 * 1024 * 64
#define EC_EPHEMERAL_KEY_PADDED_SIZE    256
#define ARGON2_DEFAULT_SALT_SIZE        32
#define ARGON2ID_VAR                    0x00
#define ARGON2I_VAR                     0x01
#define ARGON2D_VAR                     0x02
#define ARGON2_DEFAULT_ITERATIONS       16
#define ARGON2_DEFAULT_THREADS          4
#define ARGON2_DEFAULT_MEM_DEGREE       20

/* Metadata structure
*   ...encrypted data...

*   [RSA]
*   RSA payload (key, iv, tag) (pad)
*   RSA payload data size (2 bytes)

*   [Argon2]
*   Plain AES verification tag (16 bytes)
*   Argon2 variant (id, i, d, 1 byte)
*   Argon2 iterations (4 bytes)
*   Argon2 threads (4 bytes)
*   Argon2 memory degree (1 byte)
*   Argon2 salt (32 bytes)

*   [ECIES]
*   Plain AES verification tag (16 bytes)
*   Argon2 variant (id, i, d, 1 byte)
*   Argon2 iterations (4 bytes)
*   Argon2 threads (4 bytes)
*   Argon2 memory degree (1 byte)
*   Argon2 salt (32 bytes)
*   EC ephemeral public key (256 bytes) (pad)

*   [General]
*   Key management opcode (RSA/Argon2/ECIES, 1 byte)
*   AES verification tag opcode (attached/detached, 1 byte)
*   Magic signature (8 byte)
*/

const unsigned int CERBERUS_SIGNATURE_SIZE = 8;
const unsigned char CERBERUS_FILE_SIGNATURE[CERBERUS_SIGNATURE_SIZE] = { 0x3a, 0x7f, 0x7c, 0x72, 0xbc, 0x94, 0xae, 0xda };

const unsigned char AES_KEY_OPCODE_SIZE = 0x01;
const unsigned char AES_TAG_OPCODE_SIZE = 0x01;
const unsigned char AES_ENC_OPT_RSA = 0x00;
const unsigned char AES_ENC_OPT_KEY = 0x01;
const unsigned char AES_ENC_OPT_ECC = 0x02;
const unsigned char AES_ENC_OPT_TAG_ATTACHED = 0x00;
const unsigned char AES_ENC_OPT_TAG_DETACHED = 0x01;

const unsigned int RSA_METADATA_SIZE    = 2;
const unsigned int ARGON2_METADATA_SIZE = 1 + 4 + 4 + 1 + ARGON2_DEFAULT_SALT_SIZE;
const unsigned int ECIES_METADATA_SIZE  = ARGON2_METADATA_SIZE + EC_EPHEMERAL_KEY_PADDED_SIZE;

class Cerberus
{
public:
  Cerberus();
  Cerberus(const std::string &_sIn, const std::string &_sOut);

  bool encryptFile();
  bool decryptFile();
  void processWithRsa();
  void processWithKeys();
  void processWithEcc();
  void setInOutPaths(const std::string &_sIn, const std::string &_sOut);
  void unsetInOutPaths();
  void setRsaKey(RSA *_rsaKey);
  bool setEcKey(EC_KEY *_ecKey);
  void setPassphrase(const std::vector<unsigned char> &_vPassphraseBytes);
  void setKeyFileData(const std::vector<unsigned char> &_vKeyFileBytes);
  void unsetRsaKey();
  void unsetEcKey();
  void unsetPassphrase();
  void unsetKeyFileData();
  void setArgonParams(const unsigned char &_ucVariant, const unsigned int &_uiIterations, const unsigned int &_uiThreads, const unsigned char &_ucMemory);
  void detachTag(const std::string &_sTag);
  void attachTag();
  void setForce();
  void unsetForce();
  void reset();

  ~Cerberus();

private:
  unsigned char ucKeyManagementOpt = AES_ENC_OPT_RSA;
  bool bDetachHeader = false;
  bool bForce = false;

  std::string sIn;
  std::string sOut;
  std::string sTag;

  std::vector<unsigned char> vPassphraseBytes, vKeyFileBytes;
  
  RSA *rsaKey               = NULL;
  EC_KEY *ecKey             = NULL;
  EC_GROUP *ecGroup         = NULL;
  unsigned int iEcPubSize   = 0;
  int iEcPointCapacity      = 0;
  int iEcGroup              = 0;

  std::vector<unsigned char> vEcPub;

  unsigned char ucArgonVariant    = ARGON2ID_VAR;
  unsigned int uiArgonIterations  = ARGON2_DEFAULT_ITERATIONS;
  unsigned int uiArgonThreads     = ARGON2_DEFAULT_THREADS;
  unsigned char ucArgonMemory     = ARGON2_DEFAULT_MEM_DEGREE;

  void _reset();
  bool _encryptFile();
  bool _decryptFile();
  bool deriveAesKeys(const std::vector<unsigned char> &_vSecretSequence, const std::vector<unsigned char> &_vSalt, std::vector<unsigned char> &_vKey, std::vector<unsigned char> &_vIv);
};

#endif
