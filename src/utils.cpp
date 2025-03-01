#include "utils.hpp"

utils::utils()
{

}

bool utils::IsFileExist(const std::string &filename)
{
  int fd = open(filename.c_str(), O_RDONLY);
  if (fd == -1)
  {
    return false;
  }
  close(fd);
  return true;
}

bool utils::ReadFile(
  const std::string &filename, std::vector<unsigned char> &vOut,
  const unsigned long long &ullLimit, const unsigned long long &ullOffset)
{
  int fd = open(filename.c_str(), O_RDONLY);
  if (fd == -1)
  {
    return false;
  }
  off_t size_is = lseek64(fd, 0, SEEK_END);

  if (size_is <= 0 || size_is < ullLimit || size_is <= ullOffset)
  {
    close(fd);
    return false;
  }
  if (lseek64(fd, ullOffset, SEEK_SET) < 0)
  {
    close(fd);
    return false;
  }
  size_is -= ullOffset;

  !ullLimit ? 0 : size_is = ullLimit;

  vOut.resize(size_is > vOut.max_size() ? vOut.max_size() : size_is, 0);

  if (read(fd, reinterpret_cast<void *>(&vOut[0]), vOut.size()) != vOut.size())
  {
    close(fd);
    return false;
  }
  close(fd);
  return true;
}

bool utils::WriteFile(const std::string &filename, const std::vector<unsigned char> &vIn, const unsigned int &flags)
{
  if (vIn.empty())
  {
    return false;
  }

  int fd = open(filename.c_str(), O_WRONLY | flags, 0644);
  if (fd == -1)
  {
    return false;
  }

  if (write(fd, reinterpret_cast<const void *>(&vIn[0]), vIn.size()) != vIn.size())
  {
    close(fd);
    return false;
  }
  close(fd);
  return true;
}

int utils::OpenFile(const std::string &filename, const mode_t &flags, long long &llRetSize)
{
  int fd = open(filename.c_str(), flags, S_IRWXU); // S_IRWXU will be ignored in case open for reading
  if (fd != -1)
  {
    off_t ret = lseek64(fd, 0, SEEK_END);
    if (ret < 0 || lseek64(fd, 0, SEEK_SET) < 0)
    {
      close(fd);
      return -1;
    }
    llRetSize = ret;
  }
  return fd;
}

bool utils::SetSeekFileOffset(int &fd, const long long &llOffset)
{
  if (lseek64(fd, llOffset, SEEK_SET) == -1)
  {
    return false;
  }
  return true;
}

ssize_t utils::ReadFileChunk(int &fd, const long long &chunk, std::vector<unsigned char> &vOut)
{
  return read(fd, reinterpret_cast<void *>(&vOut[0]), chunk);
}

ssize_t utils::WriteFileChunk(int &fd, const std::vector<unsigned char> &vIn, const long long &chunk)
{
  return write(fd, reinterpret_cast<const void *>(&vIn[0]), chunk);
}

void utils::CloseFile(int &fd)
{
  close(fd);
}

unsigned long long utils::GetFileSize(const std::string &filename)
{
  int fd = open(filename.c_str(), O_RDONLY | O_NOATIME);

  if (fd == -1)
  {
    return 0;
  }

  const unsigned long long size_is = lseek64(fd, 0, SEEK_END);
  close(fd);

  return size_is;
}

bool utils::Is32BitProcess()
{
  if (sizeof(void *) == 4)
  {
    return true;
  }
  else
  {
    return false;
  }
}

void utils::memset_sec(void *p, const unsigned long long &ullSize, bool &bIsZeroed)
{
  unsigned char *d = (unsigned char*)p;

  for (unsigned long long i = 0; i < ullSize; ++i)
  {
    (*d++) = 0x00;
  }

  d = (unsigned char*)p;

  for (unsigned long long i = 0; i < ullSize; ++i)
  {
    if ((*d++) != 0x00)
    {
      bIsZeroed = false;
      return;
    }
  }

  bIsZeroed = true;
}

std::string utils::StringFromVector(const std::vector<unsigned char> &data)
{
  return std::string(data.begin(), data.end());
}

std::vector<unsigned char> utils::VectorFromString(const std::string &data)
{
  return std::vector<unsigned char>(data.begin(), data.end());
}

std::vector<unsigned char> utils::sha256(const std::vector<unsigned char> &input)
{
  std::vector<unsigned char> hash;
  hash.resize(SHA256_DIGEST_LENGTH);

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, input.data(), input.size());
  SHA256_Final(reinterpret_cast<unsigned char *>(&hash[0]), &sha256);

  return hash;
}

std::vector<unsigned char> utils::sha512(const std::vector<unsigned char> &input)
{
  std::vector<unsigned char> hash;
  hash.resize(SHA512_DIGEST_LENGTH);

  SHA512_CTX sha512;
  SHA512_Init(&sha512);
  SHA512_Update(&sha512, input.data(), input.size());
  SHA512_Final(reinterpret_cast<unsigned char *>(&hash[0]), &sha512);

  return hash;
}

std::vector<unsigned char> utils::md5(const std::vector<unsigned char> &input)
{
  std::vector<unsigned char> hash;
  hash.resize(MD5_DIGEST_LENGTH);

  MD5(input.data(), input.size(), reinterpret_cast<unsigned char *>(&hash[0]));

  return hash;
}

// Version 4 (random) / Variant 1 (10xx2)
bool utils::gen_rand_uuid(std::vector<unsigned char> &vOut, const unsigned int &uiLen, const unsigned short &usLeft, const unsigned short &usRight)
{
  if (uiLen != 16 || vOut.size() != uiLen)
  {
    return false;
  }
  if (!genRandBytes(vOut, 16))
  {
    return false;
  }

  unsigned char ucRandBits = 0;
  ucRandBits = (vOut[6] << 4);
  vOut[6] = 0x40 | (ucRandBits >> 4);
  ucRandBits = (vOut[8] << 2);
  vOut[8] = 0x80 | (ucRandBits >> 2);
  vOut[12] = ((usLeft >> 8) & 0xff);
  vOut[13] = (usLeft & 0xff);
  vOut[14] = ((usRight >> 8) & 0xff);
  vOut[15] = (usRight & 0xff);

  return true;
}

// 8-4-4-4-12
std::string utils::bytes_to_uuid(const std::vector<unsigned char> &input)
{
  if (input.size() != 16)
  {
    return std::string();
  }

  std::string sHex = bytes_to_hex(input);
  std::string sUUID;
  sUUID.insert(sUUID.end(), sHex.begin(), sHex.begin() + 8);
  sUUID.push_back('-');
  sUUID.insert(sUUID.end(), sHex.begin() + 8, sHex.begin() + 8 + 4);
  sUUID.push_back('-');
  sUUID.insert(sUUID.end(), sHex.begin() + 8 + 4, sHex.begin() + 8 + 4 + 4);
  sUUID.push_back('-');
  sUUID.insert(sUUID.end(), sHex.begin() + 8 + 4 + 4, sHex.end());

  return sUUID;
}

// FIXME: add version validation by RFC
bool utils::validate_uuid(const std::string &input)
{
  if (input.size() != 36)
  {
    return false;
  }
  if (input[8] != '-' || input[12] != '-' || input[16] != '-' || input[20] != '-')
  {
    return false;
  }

  return true;
}

std::string utils::bytes_to_hex(const std::vector<unsigned char> &input)
{
  const unsigned int len = input.size();
  if (!len)
  {
    return std::string();
  }

  std::stringstream ss;

  for (unsigned int i = 0; i < len; ++i)
  {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)input[i];
  }

  return ss.str();
}

unsigned int utils::fillUnsignedInt(const std::vector<unsigned char> &vData)
{
  unsigned int uiRetval = 0, i = 0;
  if (vData.size() != sizeof(unsigned int))
  {
    return uiRetval;
  }

  uiRetval = vData[i++];
  uiRetval <<= 8;
  uiRetval |= vData[i++];
  uiRetval <<= 8;
  uiRetval |= vData[i++];
  uiRetval <<= 8;
  uiRetval |= vData[i];

  return uiRetval;
}

unsigned long long utils::fillUnsignedLongLong(const std::vector<unsigned char> &vData)
{
  unsigned long long ullRetval = 0, i = 0;
  if (vData.size() != sizeof(unsigned long long))
  {
    return ullRetval;
  }

  ullRetval = vData[i++];
  ullRetval <<= 8;
  ullRetval |= vData[i++];
  ullRetval <<= 8;
  ullRetval |= vData[i++];
  ullRetval <<= 8;
  ullRetval |= vData[i++];
  ullRetval <<= 8;
  ullRetval |= vData[i++];
  ullRetval <<= 8;
  ullRetval |= vData[i++];
  ullRetval <<= 8;
  ullRetval |= vData[i++];
  ullRetval <<= 8;
  ullRetval |= vData[i++];

  return ullRetval;
}

void utils::divideUnsignedIntToShorts(const unsigned int &uiData, unsigned short &usLeft, unsigned short &usRight)
{
  usLeft = ((uiData >> 16) & 0xffff);
  usRight = (uiData & 0xffff);
}

unsigned int utils::combineShortsToUnsignedInt(const unsigned short &usLeft, const unsigned short &usRight)
{
  unsigned int uiReval = (unsigned int)(usLeft << 16);
  uiReval |= usRight;
  return uiReval;
}

std::string utils::sToLower(const std::string &sIn)
{
  std::string sOut;

  for (const auto &x : sIn)
  {
    if (x >= 65 && x <= 90)
    {
      sOut += (char)(x + 32);
      continue;
    }
    sOut += x;
  }
  return sOut;
}

bool utils::genRandBytes(std::vector<unsigned char> &vOut, const unsigned int &uiLen)
{
  if (vOut.size() != uiLen)
  {
    return false;
  }
  if (1 != RAND_priv_bytes(reinterpret_cast<unsigned char *>(&vOut[0]), uiLen))
  {
    return false;
  }
  return true;
}

int utils::strCurveToNID(const std::string &sCurveName)
{
  return OBJ_txt2nid(sCurveName.c_str());
}

bool utils::genKeyPairRSA(
  const std::string &sPathPublic,
  const std::string &sPathPrivate,
  const bool &bEnc,
  unsigned char* ucPwd,
  const unsigned int &uiPwdLen)
{
  FILE *fp = NULL;
  RSA *keypair = NULL;
  BIGNUM *bne = NULL;
  int ret = 0;
  const EVP_CIPHER *enc = bEnc ? EVP_aes_256_xts() : NULL;

  bne = BN_new();
  ret = BN_set_word(bne, RSA_F4);

  if (ret != 1)
  {
    BN_free(bne);
    return false;
  }

  keypair = RSA_new();
  ret = RSA_generate_key_ex(keypair, DEFAULT_RSA_KEY_SIZE, bne, NULL);

  if (ret != 1)
  {
    RSA_free(keypair);
    BN_free(bne);
    return false;
  }

  fp = fopen(sPathPrivate.c_str(), "w");
  if (fp == NULL)
  {
    RSA_free(keypair);
    BN_free(bne);
    return false;
  }
  PEM_write_RSAPrivateKey(fp, keypair, enc, ucPwd, uiPwdLen, NULL, NULL);
  fclose(fp);

  fp = fopen(sPathPublic.c_str(), "w");
  if (fp == NULL)
  {
    RSA_free(keypair);
    BN_free(bne);
    return false;
  }
  PEM_write_RSAPublicKey(fp, keypair);
  fclose(fp);

  RSA_free(keypair);
  BN_free(bne);

  return true;
}

bool utils::genKeyPairEC(
  const std::string &sPathPublic,
  const std::string &sPathPrivate,
  const std::string &sCurveName,
  const bool &bEnc,
  unsigned char* ucPwd,
  const unsigned int &uiPwdLen)
{
  FILE *fp = NULL;
  int eccgrp = NID_undef;
  EC_KEY *ec = NULL;
  const EVP_CIPHER *enc = bEnc ? EVP_aes_256_xts() : NULL;

  eccgrp = strCurveToNID(sCurveName);
  if (eccgrp == NID_undef)
  {
    return false;
  }

  ec = EC_KEY_new_by_curve_name(eccgrp);
  EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
  if (!EC_KEY_generate_key(ec))
  {
    EC_KEY_free(ec);
    return false;
  }

  fp = fopen(sPathPrivate.c_str(), "w");
  if (fp == NULL)
  {
    EC_KEY_free(ec);
    return false;
  }
  PEM_write_ECPrivateKey(fp, ec, enc, ucPwd, uiPwdLen, 0, NULL);
  fclose(fp);

  fp = fopen(sPathPublic.c_str(), "w");
  if (fp == NULL)
  {
    EC_KEY_free(ec);
    return false;
  }
  PEM_write_EC_PUBKEY(fp, ec);
  fclose(fp);

  EC_KEY_free(ec);

  return true;
}

bool utils::reencryptPrivRSA_PEM(
  const std::string &sPathIn,
  const std::string &sPathOut,
  unsigned char *ucOldPwd,
  const bool &bEnc,
  unsigned char *ucPwd,
  const unsigned int &uiPwdLen)
{
  FILE *fp = NULL;
  RSA *rsaKey = NULL;
  const EVP_CIPHER *enc = bEnc ? EVP_aes_256_xts() : NULL;

  rsaKey = getPrivRSA(sPathIn, ucOldPwd);

  if (rsaKey == NULL)
  {
    return false;
  }

  fp = fopen(sPathOut.c_str(), "w");
  if (fp == NULL)
  {
    RSA_free(rsaKey);
    return false;
  }

  PEM_write_RSAPrivateKey(fp, rsaKey, enc, ucPwd, uiPwdLen, 0, NULL);
  fclose(fp);

  RSA_free(rsaKey);

  return true;
}

bool utils::reencryptPrivEC_PEM(
  const std::string &sPathIn,
  const std::string &sPathOut,
  unsigned char *ucOldPwd,
  const bool &bEnc,
  unsigned char *ucPwd,
  const unsigned int &uiPwdLen)
{
  FILE *fp = NULL;
  EC_KEY *ec = NULL;
  const EVP_CIPHER *enc = bEnc ? EVP_aes_256_xts() : NULL;

  ec = getPrivEC(sPathIn, ucOldPwd);

  if (ec == NULL)
  {
    return false;
  }

  EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);

  fp = fopen(sPathOut.c_str(), "w");
  if (fp == NULL)
  {
    EC_KEY_free(ec);
    return false;
  }

  PEM_write_ECPrivateKey(fp, ec, enc, ucPwd, uiPwdLen, 0, NULL);
  fclose(fp);

  EC_KEY_free(ec);

  return true;
}

RSA * utils::getPubRSA(const std::string &sPath)
{
  RSA *rsa = NULL;
  FILE *fp = fopen(sPath.c_str(), "rb");

  if (fp == NULL)
  {
    return rsa;
  }

  if (PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL) == NULL)
  {
    fseek(fp, 0, SEEK_SET);
    PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
  }
  fclose(fp);
  return rsa;
}

EC_KEY * utils::getPubEC(const std::string &sPath)
{
  EC_KEY *ec = NULL;
  FILE *fp = fopen(sPath.c_str(), "rb");

  if (fp == NULL)
  {
    return ec;
  }

  PEM_read_EC_PUBKEY(fp, &ec, NULL, NULL);
  fclose(fp);
  return ec;
}

RSA * utils::getPrivRSA(const std::string &sPath, unsigned char *ucPwd)
{
  RSA *rsa = NULL;
  FILE *fp = fopen(sPath.c_str(), "rb");

  if (fp == NULL)
  {
    return rsa;
  }

  PEM_read_RSAPrivateKey(fp, &rsa, NULL, (void*)ucPwd);
  fclose(fp);
  return rsa;
}

EC_KEY * utils::getPrivEC(const std::string &sPath, unsigned char *ucPwd)
{
  EC_KEY *ec = NULL;
  FILE *fp = fopen(sPath.c_str(), "rb");

  if (fp == NULL)
  {
    return ec;
  }

  PEM_read_ECPrivateKey(fp, &ec, NULL, (void*)ucPwd);
  fclose(fp);
  return ec;
}

RSA * utils::getPubRSA(const std::vector<unsigned char> &vBuffer)
{
  if (vBuffer.empty())
  {
    return NULL;
  }

  BIO *bio = NULL;
  RSA *rsa = NULL;

  bio = BIO_new_mem_buf(reinterpret_cast<const void *>(&vBuffer[0]), vBuffer.size());
  if (PEM_read_bio_RSAPublicKey(bio, &rsa, 0, NULL) == NULL)
  {
    BIO_free(bio);
    bio = BIO_new_mem_buf(reinterpret_cast<const void *>(&vBuffer[0]), vBuffer.size());
    PEM_read_bio_RSA_PUBKEY(bio, &rsa, 0, NULL);
  }

  BIO_free(bio);

  return rsa;
}

EC_KEY * utils::getPubEC(const std::vector<unsigned char> &vBuffer)
{
  if (vBuffer.empty())
  {
    return NULL;
  }

  BIO *bio = NULL;
  EC_KEY *ec = NULL;

  bio = BIO_new_mem_buf(reinterpret_cast<const void *>(&vBuffer[0]), vBuffer.size());
  PEM_read_bio_EC_PUBKEY(bio, &ec, 0, NULL);

  BIO_free(bio);

  return ec;
}

RSA * utils::getPrivRSA(const std::vector<unsigned char> &vBuffer, unsigned char *ucPwd)
{
  if (vBuffer.empty())
  {
    return NULL;
  }

  BIO *bio = NULL;
  RSA *rsa = NULL;

  bio = BIO_new_mem_buf(reinterpret_cast<const void *>(&vBuffer[0]), vBuffer.size());
  PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, (void*)ucPwd);

  BIO_free(bio);

  return rsa;
}

EC_KEY * utils::getPrivEC(const std::vector<unsigned char> &vBuffer, unsigned char *ucPwd)
{
  if (vBuffer.empty())
  {
    return NULL;
  }

  BIO *bio = NULL;
  EC_KEY *ec = NULL;

  bio = BIO_new_mem_buf(reinterpret_cast<const void *>(&vBuffer[0]), vBuffer.size());
  PEM_read_bio_ECPrivateKey(bio, &ec, NULL, (void*)ucPwd);

  BIO_free(bio);

  return ec;
}

int utils::encryptRsa(const unsigned int &len, unsigned char *from, unsigned char *to, RSA *rsaKey)
{
  return RSA_public_encrypt(len, from, to, rsaKey, RSA_PKCS1_OAEP_PADDING);
}

int utils::decryptRsa(const unsigned int &len, unsigned char *from, unsigned char *to, RSA *rsaKey)
{
  return RSA_private_decrypt(len, from, to, rsaKey, RSA_PKCS1_OAEP_PADDING);
}

bool utils::ecPubToBin(const EC_KEY *ec_key, int &iGroup, std::vector<unsigned char> &vOut)
{
  const EC_GROUP *ec_group    = EC_KEY_get0_group(ec_key);
  const EC_POINT *pub         = EC_KEY_get0_public_key(ec_key);
  BIGNUM         *pub_bn      = BN_new();
  BN_CTX         *pub_bn_ctx  = BN_CTX_new();
  unsigned int    uiBinSize   = 0;
  
  iGroup = EC_GROUP_get_curve_name(ec_group);

  BN_CTX_start(pub_bn_ctx);

  EC_POINT_point2bn(ec_group, pub, POINT_CONVERSION_UNCOMPRESSED, pub_bn, pub_bn_ctx);

  uiBinSize = BN_num_bytes(pub_bn);
  vOut.resize(uiBinSize, 0);

  if (BN_bn2bin(pub_bn, &vOut[0]) != uiBinSize)
  {
    return false;
  }

  BN_CTX_end(pub_bn_ctx);
  BN_CTX_free(pub_bn_ctx);
  BN_clear_free(pub_bn);

  return true;
}

bool utils::ecPrivToBin(const EC_KEY *ec_key, std::vector<unsigned char> &vOut)
{
  const BIGNUM *priv      = EC_KEY_get0_private_key(ec_key);
  unsigned int uiBinSize  = 0;

  uiBinSize = BN_num_bytes(priv);
  vOut.resize(uiBinSize, 0);

  if (BN_bn2bin(priv, &vOut[0]) != uiBinSize)
  {
    return false;
  }

  return true;
}

EC_POINT * utils::ecPubBinToPoint(const std::vector<unsigned char> &vBuffer, const EC_GROUP *ec_group)
{
  if (vBuffer.empty())
  {
    return NULL;
  }

  BIGNUM   *pubk_bn;
  BN_CTX   *pubk_bn_ctx;

  EC_POINT *pubk_point = EC_POINT_new(ec_group);

  pubk_bn = BN_bin2bn(&vBuffer[0], vBuffer.size(), NULL);
  pubk_bn_ctx = BN_CTX_new();
  BN_CTX_start(pubk_bn_ctx);

  EC_POINT_bn2point(ec_group, pubk_bn, pubk_point, pubk_bn_ctx);

  BN_CTX_end(pubk_bn_ctx);
  BN_CTX_free(pubk_bn_ctx);
  BN_clear_free(pubk_bn);

  return pubk_point;
}

/* (TX) Generate an ephemeral EC key and associated shared symmetric key */
bool utils::eciesTXGenerateSymKey(const int &iCurve, const std::vector<unsigned char> &vPeerPubKey, std::vector<unsigned char> &vEPubKey, std::vector<unsigned char> &vSymKey)
{
  EC_KEY         *ec_key          = NULL; /* ephemeral keypair */
  const EC_GROUP *ec_group        = NULL;
  EC_POINT       *peer_pubk_point = NULL;
  int             iSymKeyBufSize  = 0;
  int             iRetval         = 0;

  /* Create and initialize a new empty key pair on the curve. */
  ec_key = EC_KEY_new_by_curve_name(iCurve);
  EC_KEY_generate_key(ec_key);
  ec_group = EC_KEY_get0_group(ec_key);

  iSymKeyBufSize = ((EC_GROUP_get_degree(ec_group) + 7) / 8);

  if (iSymKeyBufSize <= 0)
  {
    // TODO: ...
    return false;
  }
  vSymKey.resize(iSymKeyBufSize, 0);

  /* Convert the peer public key to an EC point. */
  peer_pubk_point = ecPubBinToPoint(vPeerPubKey, ec_group);

  /* Generate the shared symmetric key (diffie-hellman primitive). */
  iRetval = ECDH_compute_key(&vSymKey[0], vSymKey.size(), peer_pubk_point, ec_key, NULL);

  if (iRetval <= 0 || iRetval != iSymKeyBufSize)
  {
    // TODO: ...
    return false;
  }

  /*
   * NOTE: The private key is thrown away here...
   * With ECIES the transmitter EC key pair is a one time use only.
   */

  /* Write the ephemeral key's public key to the output buffer. */

  return ecPubToBin(ec_key, iRetval, vEPubKey);
}

/* (RX) Generate the shared symmetric key */
bool utils::eciesRXGenerateSymKey(const EC_KEY *ec_key, const std::vector<unsigned char> &vPeerPubKey, std::vector<unsigned char> &vSymKey)
{
  const EC_GROUP *ec_group        = EC_KEY_get0_group(ec_key);
  EC_POINT       *peer_pubk_point = NULL;
  int             iSymKeyBufSize  = 0;
  int             iRetval         = 0;

  iSymKeyBufSize = ((EC_GROUP_get_degree(ec_group) + 7) / 8);

  if (iSymKeyBufSize <= 0)
  {
    // TODO: ...
    return false;
  }
  vSymKey.resize(iSymKeyBufSize, 0);

  /* Convert the peer public key to an EC point. */
  peer_pubk_point = ecPubBinToPoint(vPeerPubKey, ec_group);

  /* Generate the shared symmetric key (diffie-hellman primitive). */
  iRetval = ECDH_compute_key(&vSymKey[0], vSymKey.size(), peer_pubk_point, (EC_KEY *)ec_key, NULL);

  if (iRetval <= 0 || iRetval != iSymKeyBufSize)
  {
    // TODO: ...
    return false;
  }

  return true;
}

int utils::gcm_encrypt_in_place(
  unsigned char *plaintext, int plaintext_len,
  unsigned char *aad, int aad_len,
  unsigned char *key, int key_len,
  unsigned char *iv, int iv_len,
  unsigned char *ciphertext,
  unsigned char *tag)
{
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  int ciphertext_len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: error create context");
    #endif
    return -1;
  }

  /* Initialise the encryption operation. */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: error initialise encryption operation");
    #endif
    return -1;
  }

  /*
   * Set IV length if default 12 bytes (96 bits) is not appropriate
   */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: error set IV length");
    #endif
    return -1;
  }

  /* Set key length */
  if (1 != EVP_CIPHER_CTX_set_key_length(ctx, key_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: error set key length");
    #endif
    return -1;
  }

  /* Initialise key and IV */
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: error initialise key and IV");
    #endif
    return -1;
  }

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: error initialise AAD data");
    #endif
    return -1;
  }

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: EVP_EncryptUpdate() failed");
    #endif
    return -1;
  }
  ciphertext_len = len;

  /*
   * Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: EVP_EncryptFinal_ex() failed");
    #endif
    return -1;
  }
  ciphertext_len += len;

  /* Get the tag */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt() :: error get the tag");
    #endif
    return -1;
  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int utils::gcm_decrypt_in_place(
  unsigned char *ciphertext, int ciphertext_len,
  unsigned char *aad, int aad_len,
  unsigned char *tag,
  unsigned char *key, int key_len,
  unsigned char *iv, int iv_len,
  unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len = 0;
  int plaintext_len = 0;
  int ret = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: error create context");
    #endif
    return -1;
  }

  /* Initialise the decryption operation. */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: error initialise decryption operation");
    #endif
    return -1;
  }

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: error set IV length");
    #endif
    return -1;
  }

  /* Set key length */
  if (1 != EVP_CIPHER_CTX_set_key_length(ctx, key_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: error set key length");
    #endif
    return -1;
  }

  /* Initialise key and IV */
  if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: error initialise key and IV");
    #endif
    return -1;
  }

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: error initialise AAD data");
    #endif
    return -1;
  }

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: EVP_DecryptUpdate() failed");
    #endif
    return -1;
  }
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: error set tag value");
    #endif
    return -1;
  }

  /*
   * Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0)
  {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  }
  else
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt() :: EVP_DecryptFinal_ex() tag verification failed");
    #endif
    /* Verify failed */
    return -1;
  }
}

bool utils::gcm_create_ctx_wrap(EVP_CIPHER_CTX **ctx)
{
  /* Create and initialise the context */
  if (!(*ctx = EVP_CIPHER_CTX_new()))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_create_ctx_wrap() :: error create context");
    #endif
    return false;
  }
  return true;
}

bool utils::gcm_encrypt_setup_wrap(
  EVP_CIPHER_CTX *ctx, unsigned char *aad, int aad_len,
  unsigned char *key, int key_len, unsigned char *iv, int iv_len)
{
  int len = 0;
  /* Initialise the encryption operation. */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt_setup_wrap() :: error initialise encryption operation");
    #endif
    return false;
  }

  /*
   * Set IV length if default 12 bytes (96 bits) is not appropriate
   */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt_setup_wrap() :: error set IV length");
    #endif
    return false;
  }

  /* Set key length */
  if (1 != EVP_CIPHER_CTX_set_key_length(ctx, key_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt_setup_wrap() :: error set key length");
    #endif
    return false;
  }

  /* Initialise key and IV */
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt_setup_wrap() :: error initialise key and IV");
    #endif
    return false;
  }

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt_setup_wrap() :: error initialise AAD data");
    #endif
    return false;
  }
  return true;
}

bool utils::gcm_decrypt_setup_wrap(
  EVP_CIPHER_CTX *ctx, unsigned char *aad, int aad_len,
  unsigned char *key, int key_len, unsigned char *iv, int iv_len)
{
  int len = 0;
  /* Initialise the decryption operation. */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt_setup_wrap() :: error initialise decryption operation");
    #endif
    return false;
  }

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt_setup_wrap() :: error set IV length");
    #endif
    return false;
  }

  /* Set key length */
  if (1 != EVP_CIPHER_CTX_set_key_length(ctx, key_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt_setup_wrap() :: error set key length");
    #endif
    return false;
  }

  /* Initialise key and IV */
  if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt_setup_wrap() :: error initialise key and IV");
    #endif
    return false;
  }

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt_setup_wrap() :: error initialise AAD data");
    #endif
    return false;
  }

  return true;
}

bool utils::gcm_encrypt_block_wrap(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
  if (1 != EVP_EncryptUpdate(ctx, out, &out_len, in, in_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt_block_wrap() :: EVP_EncryptUpdate() failed");
    #endif
    return false;
  }
  return true;
}

bool utils::gcm_decrypt_block_wrap(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
  if (1 != EVP_DecryptUpdate(ctx, out, &out_len, in, in_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt_block_wrap() :: EVP_DecryptUpdate() failed");
    #endif
    return false;
  }
  return true;
}

bool utils::gcm_encrypt_finalise_wrap(EVP_CIPHER_CTX *ctx, unsigned char *out, int &out_len)
{
  if (1 != EVP_EncryptFinal_ex(ctx, out, &out_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_encrypt_finalise_wrap() :: EVP_EncryptFinal_ex() failed");
    #endif
    return false;
  }
  return true;
}

bool utils::gcm_decrypt_finalise_wrap(EVP_CIPHER_CTX *ctx, unsigned char *out, int &out_len)
{
  if (1 != EVP_DecryptFinal_ex(ctx, out, &out_len))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_decrypt_finalise_wrap() :: EVP_DecryptFinal_ex() failed");
    #endif
    return false;
  }
  return true;
}

bool utils::gcm_get_tag_wrap(EVP_CIPHER_CTX *ctx, unsigned char *tag)
{
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_get_tag_wrap() :: error get the tag");
    #endif
    return false;
  }
  return true;
}

bool utils::gcm_set_tag_wrap(EVP_CIPHER_CTX *ctx, unsigned char *tag)
{
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcm_set_tag_wrap() :: error set the tag");
    #endif
    return false;
  }
  return true;
}

void utils::gcm_destroy_ctx_wrap(EVP_CIPHER_CTX **ctx)
{
  EVP_CIPHER_CTX_free(*ctx);
}

bool utils::gcm_setup_wrap(gcm_work_st *gcm_ctx, bool (*gcm_setup)(EVP_CIPHER_CTX*, unsigned char*, int, unsigned char*, int, unsigned char*, int))
{
  return gcm_setup(gcm_ctx->ctx, (unsigned char*)AAD_DATA, AAD_DATA_len,
    gcm_ctx->vKey.data(), gcm_ctx->vKey.size(), gcm_ctx->vIv.data(), gcm_ctx->vIv.size());
}

bool utils::gcmProcessFile(
  gcm_work_st *gcm_ctx, const std::string &sFileIn, const std::string &sFileOut,
  bool (*gcm_process)(EVP_CIPHER_CTX*, unsigned char*, int, unsigned char*, int&),
  unsigned long long &ullProcessedBytes, const long long &readTill)
{
  int fdIn = 0;
	int fdOut = 0;
	long long llFileSize = 0;
	long long llTmp = 0;
  int gcmProcessed = 0;
	int readed = 0;
  unsigned long long gcmTotalProcessed = 0;
	unsigned long long bytesReaded = 0;
	unsigned long long bytesWrited = 0;
  bool bReadTillReached = false;
	const unsigned int chunkSize = GCM_PROCESS_CHUNK_SIZE;
	std::vector<unsigned char> vBuffer(chunkSize, 0);

	const mode_t flagsRead = O_RDONLY | O_NOATIME;
  const mode_t flagsWrite = O_CREAT | O_EXCL | O_WRONLY;

  fdIn = OpenFile(sFileIn, flagsRead, llFileSize);
	if (fdIn == -1)
	{
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmProcessFile() :: error open input file: " << sFileIn);
    #endif
		return false;
	}
  if (readTill != 0 && llFileSize < readTill)
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmProcessFile() :: size of input file is wrong");
    #endif
    CloseFile(fdIn);
    return false;
  }

	fdOut = OpenFile(sFileOut, flagsWrite, llTmp);
	if (fdOut == -1)
	{
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmProcessFile() :: error open output file: " << sFileOut);
    #endif
		return false;
	}

  while ((readed = ReadFileChunk(fdIn, chunkSize, vBuffer)) > 0 && !bReadTillReached)
	{
		bytesReaded += readed;

    if (readTill != 0 && bytesReaded > readTill)
    {
      bytesReaded -= readed;
      readed = readTill - bytesWrited;
      bytesReaded += readed;
      bReadTillReached = true;
    }

    if (!gcm_process(gcm_ctx->ctx, vBuffer.data(), readed, &vBuffer[0], gcmProcessed))
    {
      #ifdef __DEBUG_ENABLED
      LOG_ERROR("gcmProcessFile() :: error during gcm block processing");
      #endif
      CloseFile(fdIn);
      CloseFile(fdOut);
      return false;
    }

		int writed = WriteFileChunk(fdOut, vBuffer, gcmProcessed);
		if (writed != gcmProcessed)
		{
      #ifdef __DEBUG_ENABLED
      LOG_ERROR("gcmProcessFile() :: error write to output file");
      #endif
      CloseFile(fdIn);
			CloseFile(fdOut);
			return false;
		}
		bytesWrited += writed;
    gcmTotalProcessed += gcmProcessed;
	}

  CloseFile(fdIn);
  CloseFile(fdOut);

  if (readed < 0)
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmProcessFile() :: error read from input file");
    #endif
    return false;
  }

  if ((readTill && gcmTotalProcessed != readTill) || (!readTill && llFileSize != gcmTotalProcessed))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmProcessFile() :: not all GCM data have been processed");
    #endif
    return false;
  }

  ullProcessedBytes = gcmTotalProcessed;

  return true;
}

bool utils::gcmEncryptFileWrap(
  const std::string &sIn, const std::string &sOut,
  const std::vector<unsigned char> &vKey, const std::vector<unsigned char> &vIv,
  unsigned long long &ullProcessedBytes, std::vector<unsigned char> &vTag)
{
  if (sIn == sOut)
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmEncryptFileWrap() :: input and output file paths cannot be equal");
    #endif
    return false;
  }
  if (vKey.size() != AES256_KEY_SIZE || vIv.size() != IV_SIZE)
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmEncryptFileWrap() :: error init aes key and/or iv");
    #endif
    return false;
  }

  unsigned char *finalBuffer = NULL;
  int finalLen = 0;
  gcm_work_st gcm_ctx;
  gcm_ctx.vIv = vIv;
  gcm_ctx.vKey = vKey;
  gcm_ctx.vTag.resize(TAG_SIZE, 0);

  if (!gcm_create_ctx_wrap(&gcm_ctx.ctx))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmEncryptFileWrap() :: error create ctx");
    #endif
    return false;
  }

  if (!gcm_setup_wrap(&gcm_ctx, gcm_encrypt_setup_wrap))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmEncryptFileWrap() :: gcm_setup_wrap() failed");
    #endif
    gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
    return false;
  }

  if (!gcmProcessFile(&gcm_ctx, sIn, sOut, gcm_encrypt_block_wrap, ullProcessedBytes))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmEncryptFileWrap() :: gcmProcessFile() failed");
    #endif
    gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
    return false;
  }

  if (!gcm_encrypt_finalise_wrap(gcm_ctx.ctx, finalBuffer, finalLen))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmEncryptFileWrap() :: gcm_encrypt_finalise_wrap() failed");
    #endif
    gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
    return false;
  }

  if (!gcm_get_tag_wrap(gcm_ctx.ctx, &gcm_ctx.vTag[0]))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmEncryptFileWrap() :: gcm_get_tag_wrap() failed");
    #endif
    gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
    return false;
  }

  bool bIsMemZeroed = false;
  memset_sec(&gcm_ctx.vKey[0], gcm_ctx.vKey.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    #ifdef __DEBUG_ENABLED
    LOG_WARNING("gcmEncryptFileWrap() :: AES key memory area was not properly cleaned");
    #endif
  }
  
  bIsMemZeroed = false;
  memset_sec(&gcm_ctx.vIv[0], gcm_ctx.vIv.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    #ifdef __DEBUG_ENABLED
    LOG_WARNING("gcmEncryptFileWrap() :: AES iv memory area was not properly cleaned");
    #endif
  }

  vTag = gcm_ctx.vTag;
  gcm_destroy_ctx_wrap(&gcm_ctx.ctx);

  return true;
}

bool utils::gcmDecryptFileWrap(
  const std::string &sIn, const std::string &sOut,
  const std::vector<unsigned char> &vKey, const std::vector<unsigned char> &vIv,
  const std::vector<unsigned char> &vTag, const long long &llReadLimit,
  unsigned long long &ullProcessedBytes, const bool &bSkipVerify)
{
  unsigned char *finalBuffer = NULL;
  int finalLen = 0;
  gcm_work_st gcm_ctx;
  gcm_ctx.vKey = vKey;
  gcm_ctx.vIv = vIv;
  gcm_ctx.vTag = vTag;

  if (vKey.size() != AES256_KEY_SIZE || vIv.size() != IV_SIZE)
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmDecryptFileWrap() :: error init aes key and/or iv");
    #endif
    return false;
  }
  if (!bSkipVerify && vTag.size() != TAG_SIZE)
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmDecryptFileWrap() :: error init tag with size [" << vTag.size() << "]");
    #endif
    return false;
  }
  else
  {
    gcm_ctx.vTag.resize(TAG_SIZE, 0);
  }

  if (GetFileSize(sIn) < llReadLimit || !llReadLimit)
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmDecryptFileWrap() :: size of input file is wrong [" << sIn << "]");
    #endif
    return false;
  }

  if (!gcm_create_ctx_wrap(&gcm_ctx.ctx))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmDecryptFileWrap() :: error create ctx");
    #endif
    return false;
  }

  if (!gcm_setup_wrap(&gcm_ctx, gcm_decrypt_setup_wrap))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmDecryptFileWrap() :: gcm_setup_wrap() failed");
    #endif
    gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
    return false;
  }

  if (!gcmProcessFile(&gcm_ctx, sIn, sOut, gcm_decrypt_block_wrap, ullProcessedBytes, llReadLimit))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmDecryptFileWrap() :: gcmProcessFile() failed");
    #endif
    gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
    return false;
  }

  if (!gcm_set_tag_wrap(gcm_ctx.ctx, &gcm_ctx.vTag[0]))
  {
    #ifdef __DEBUG_ENABLED
    LOG_ERROR("gcmDecryptFileWrap() :: gcm_set_tag_wrap() failed");
    #endif
    gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
    return false;
  }

  /* Verify result */
  if (!bSkipVerify)
  {
    if (!gcm_decrypt_finalise_wrap(gcm_ctx.ctx, finalBuffer, finalLen))
    {
      #ifdef __DEBUG_ENABLED
      LOG_ERROR("gcmDecryptFileWrap() :: gcm_decrypt_finalise_wrap() failed");
      #endif
      gcm_destroy_ctx_wrap(&gcm_ctx.ctx);
      return false;
    }
  }
  else
  {
    #ifdef __DEBUG_ENABLED
    LOG_WARNING("gcmDecryptFileWrap() :: skipping AES-GCM tag verification");
    #endif
  }

  bool bIsMemZeroed = false;
  memset_sec(&gcm_ctx.vKey[0], gcm_ctx.vKey.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    #ifdef __DEBUG_ENABLED
    LOG_WARNING("gcmDecryptFileWrap() :: AES key memory area was not properly cleaned");
    #endif
  }
  
  bIsMemZeroed = false;
  memset_sec(&gcm_ctx.vIv[0], gcm_ctx.vIv.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    #ifdef __DEBUG_ENABLED
    LOG_WARNING("gcmDecryptFileWrap() :: AES iv memory area was not properly cleaned");
    #endif
  }

  gcm_destroy_ctx_wrap(&gcm_ctx.ctx);

  return true;
}

void utils::PBKDF2_HMAC_SHA_512(unsigned char* pass, int passlen, unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, unsigned char* binResult)
{
  PKCS5_PBKDF2_HMAC((const char*)pass, passlen, salt, saltlen, iterations, EVP_sha512(), outputBytes, binResult);
}

bool utils::argon2id(
  unsigned char* pass, uint32_t passlen, unsigned char* salt, uint32_t saltlen,
  uint32_t iterations, uint32_t memKibiBytes, uint32_t threads, uint32_t hashlen, unsigned char* hash,
  unsigned char* optSecret, uint32_t secretlen)
{
  argon2_context context = {
  hash,  /* output array, at least HASHLEN in size */
  hashlen, /* digest length */
  pass, /* password array */
  passlen, /* password length */
  salt,  /* salt array */
  saltlen, /* salt length */
  optSecret, secretlen, /* optional secret data */
  NULL, 0, /* optional associated data */
  iterations, memKibiBytes, threads, threads,
  ARGON2_VERSION_13, /* algorithm version */
  NULL, NULL, /* custom memory allocation / deallocation functions */
  /* by default only internal memory is cleared (pwd is not wiped) */
  ARGON2_FLAG_CLEAR_PASSWORD
  };

  int rc = argon2id_ctx(&context);

  return ARGON2_OK == rc;
}

bool utils::argon2i(
  unsigned char* pass, uint32_t passlen, unsigned char* salt, uint32_t saltlen,
  uint32_t iterations, uint32_t memKibiBytes, uint32_t threads, uint32_t hashlen, unsigned char* hash,
  unsigned char* optSecret, uint32_t secretlen)
{
  argon2_context context = {
  hash,  /* output array, at least HASHLEN in size */
  hashlen, /* digest length */
  pass, /* password array */
  passlen, /* password length */
  salt,  /* salt array */
  saltlen, /* salt length */
  optSecret, secretlen, /* optional secret data */
  NULL, 0, /* optional associated data */
  iterations, memKibiBytes, threads, threads,
  ARGON2_VERSION_13, /* algorithm version */
  NULL, NULL, /* custom memory allocation / deallocation functions */
  /* by default only internal memory is cleared (pwd is not wiped) */
  ARGON2_FLAG_CLEAR_PASSWORD
  };

  int rc = argon2i_ctx(&context);

  return ARGON2_OK == rc;
}

bool utils::argon2d(
  unsigned char* pass, uint32_t passlen, unsigned char* salt, uint32_t saltlen,
  uint32_t iterations, uint32_t memKibiBytes, uint32_t threads, uint32_t hashlen, unsigned char* hash,
  unsigned char* optSecret, uint32_t secretlen)
{
  argon2_context context = {
  hash,  /* output array, at least HASHLEN in size */
  hashlen, /* digest length */
  pass, /* password array */
  passlen, /* password length */
  salt,  /* salt array */
  saltlen, /* salt length */
  optSecret, secretlen, /* optional secret data */
  NULL, 0, /* optional associated data */
  iterations, memKibiBytes, threads, threads,
  ARGON2_VERSION_13, /* algorithm version */
  NULL, NULL, /* custom memory allocation / deallocation functions */
  /* by default only internal memory is cleared (pwd is not wiped) */
  ARGON2_FLAG_CLEAR_PASSWORD
  };

  int rc = argon2d_ctx(&context);

  return ARGON2_OK == rc;
}

utils::~utils()
{

}

