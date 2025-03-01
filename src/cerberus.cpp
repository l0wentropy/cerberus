#include "cerberus.hpp"

Cerberus::Cerberus()
{

}

Cerberus::Cerberus(const std::string &_sIn, const std::string &_sOut)
{
  sIn = _sIn;
  sOut = _sOut;
}

bool Cerberus::encryptFile()
{
  if (sIn.empty() || sOut.empty())
  {
    printf("Input and output files paths must be set first\n");
    return false;
  }
  if (ucKeyManagementOpt == AES_ENC_OPT_RSA && rsaKey == NULL)
  {
    printf("RSA key is not loaded\n");
    return false;
  }
  else if (ucKeyManagementOpt == AES_ENC_OPT_ECC && ecKey == NULL)
  {
    printf("EC key is not loaded\n");
    return false;
  }
  else if (ucKeyManagementOpt == AES_ENC_OPT_KEY && vPassphraseBytes.empty() && vKeyFileBytes.empty())
  {
    printf("Either passphrase or key file data must be loaded\n");
    return false;
  }

  return _encryptFile();
}

bool Cerberus::decryptFile()
{
  if (sIn.empty() || sOut.empty())
  {
    printf("Input and output files paths must be set first\n");
    return false;
  }
  if (ucKeyManagementOpt == AES_ENC_OPT_RSA && rsaKey == NULL)
  {
    printf("RSA key is not loaded\n");
    return false;
  }
  else if (ucKeyManagementOpt == AES_ENC_OPT_ECC && ecKey == NULL)
  {
    printf("EC key is not loaded\n");
    return false;
  }
  else if (ucKeyManagementOpt == AES_ENC_OPT_KEY && vPassphraseBytes.empty() && vKeyFileBytes.empty())
  {
    printf("Either passphrase or key file data must be loaded\n");
    return false;
  }

  return _decryptFile();
}

void Cerberus::processWithRsa()
{
  ucKeyManagementOpt = AES_ENC_OPT_RSA;
}

void Cerberus::processWithKeys()
{
  ucKeyManagementOpt = AES_ENC_OPT_KEY;
}

void Cerberus::processWithEcc()
{
  ucKeyManagementOpt = AES_ENC_OPT_ECC;
}

void Cerberus::setInOutPaths(const std::string &_sIn, const std::string &_sOut)
{
  sIn = _sIn;
  sOut = _sOut;
}

void Cerberus::unsetInOutPaths()
{
  sIn.clear();
  sOut.clear();
}

void Cerberus::setRsaKey(RSA *_rsaKey)
{
  rsaKey = _rsaKey;
}

bool Cerberus::setEcKey(EC_KEY *_ecKey)
{
  ecKey = _ecKey;
  ecGroup = utils::ecGetGroup(ecKey);
  iEcGroup = utils::ecGetGroup(ecGroup);
  iEcPointCapacity = utils::ecGetECDHSize(ecGroup);

  return utils::ecPubToBin(ecKey, vEcPub);
}

void Cerberus::setPassphrase(const std::vector<unsigned char> &_vPassphraseBytes)
{
  vPassphraseBytes = _vPassphraseBytes;
}

void Cerberus::setKeyFileData(const std::vector<unsigned char> &_vKeyFileBytes)
{
  vKeyFileBytes = _vKeyFileBytes;
}

void Cerberus::unsetRsaKey()
{
  if (rsaKey)
  {
    RSA_free(rsaKey);
  }
  rsaKey = NULL;
}

void Cerberus::unsetEcKey()
{
  if (ecKey)
  {
    EC_KEY_free(ecKey);
  }
  ecKey = NULL;
  ecGroup = NULL;
  iEcPointCapacity = 0;
  iEcGroup = 0;
  vEcPub.clear();
}

bool Cerberus::unsetPassphrase()
{
  bool bIsMemZeroed = false;
  if (!vPassphraseBytes.empty())
  {
    utils::memset_sec(&vPassphraseBytes[0], vPassphraseBytes.size(), bIsMemZeroed);
    vPassphraseBytes.clear();
  }
  return bIsMemZeroed;
}

bool Cerberus::unsetKeyFileData()
{
  bool bIsMemZeroed = false;
  if (!vKeyFileBytes.empty())
  {
    utils::memset_sec(&vKeyFileBytes[0], vKeyFileBytes.size(), bIsMemZeroed);
    vKeyFileBytes.clear();
  }
  return bIsMemZeroed;
}

void Cerberus::setArgonParams(const unsigned char &_ucVariant, const unsigned int &_uiIterations, const unsigned int &_uiThreads, const unsigned char &_ucMemory)
{
  ucArgonVariant = _ucVariant;
  uiArgonIterations = _uiIterations;
  uiArgonThreads = _uiThreads;
  ucArgonMemory = _ucMemory;
}

void Cerberus::detachTag(const std::string &_sTag)
{
  sTag = _sTag;
  bDetachHeader = true;
}

void Cerberus::attachTag()
{
  sTag.clear();
  bDetachHeader = false;
}

void Cerberus::setForce()
{
  bForce = true;
}

void Cerberus::unsetForce()
{
  bForce = false;
}

void Cerberus::reset()
{
  _reset();
}

Cerberus::~Cerberus()
{

}

void Cerberus::_reset()
{
  processWithRsa();
  attachTag();
  unsetForce();
  unsetInOutPaths();
  unsetRsaKey();
  unsetEcKey();
  unsetPassphrase();
  unsetKeyFileData();
  setArgonParams(ARGON2ID_VAR, ARGON2_DEFAULT_ITERATIONS, ARGON2_DEFAULT_THREADS, ARGON2_DEFAULT_MEM_DEGREE);
}

bool Cerberus::_encryptFile()
{
  bool bIsMemZeroed = false;
  unsigned long long ullProcessedBytes = 0;
  std::vector<unsigned char> vSalt(ARGON2_DEFAULT_SALT_SIZE);
  std::vector<unsigned char> vKey(AES256_KEY_SIZE, 0), vIv(IV_SIZE, 0), vTag(TAG_SIZE, 0);
  std::vector<unsigned char> vEcEphemeral, vAppend;
  const mode_t flagsWrite = O_WRONLY | O_APPEND;

  if (ucKeyManagementOpt == AES_ENC_OPT_RSA)
  {
    if (!utils::genRandBytes(vKey, vKey.size()) || !utils::genRandBytes(vIv, vIv.size()))
    {
      printf("Cannot generate random bytes for AES key or/and IV\n");
      return false;
    }
  }
  else if (ucKeyManagementOpt == AES_ENC_OPT_KEY || ucKeyManagementOpt == AES_ENC_OPT_ECC)
  {
    if (!utils::genRandBytes(vSalt, vSalt.size()))
    {
      printf("Cannot generate random bytes for salt\n");
      return false;
    }

    std::vector<unsigned char> vSecretSequence;

    if (ucKeyManagementOpt == AES_ENC_OPT_KEY)
    {
      vSecretSequence = vPassphraseBytes;
      vSecretSequence.insert(vSecretSequence.end(), vKeyFileBytes.begin(), vKeyFileBytes.end());

      if (!vPassphraseBytes.empty())
      {
        printf("Passphrase used\n");
      }
      if (!vKeyFileBytes.empty())
      {
        printf("Key file used\n");
      }
    }
    else
    {
      if (!utils::eciesTXGenerateSymKey(iEcGroup, vEcPub, vEcEphemeral, vSecretSequence))
      {
        printf("Cannot generate TX symmetric key\n");
        return false;
      }

      if (vEcEphemeral.size() > EC_EPHEMERAL_KEY_PADDED_SIZE)
      {
        // TODO: ...
        printf("EC ephemeral key too long\n");
        return false;
      }

      const unsigned int uiPadded = EC_EPHEMERAL_KEY_PADDED_SIZE - vEcEphemeral.size();
      if (uiPadded)
      {
        std::vector<unsigned char> vPadding(uiPadded);
        if (!utils::genRandBytes(vPadding, vPadding.size()))
        {
          printf("Cannot generate random bytes for padding\n");
          return false;
        }

        vEcEphemeral.insert(vEcEphemeral.end(), vPadding.begin(), vPadding.end());
      }

      printf("ECIES:");
      printf("\n\t");
      printf("Curve [%s]", utils::NID2Str(iEcGroup).c_str());
      printf("\n\t");
      printf("Affiliate point size [%lu]", vSecretSequence.size());
      printf("\n\t");
      printf("EC ephemeral key size [%lu] (padded [%lu])", vEcEphemeral.size() - uiPadded, vEcEphemeral.size());
      
      printf("\n\t");
      printf("\n");
    }

    printf("Argon2 options:");
    printf("\n\t");
    if (ucArgonVariant == ARGON2ID_VAR)
    {
      printf("Variant [Argon2id]");
    }
    else if (ucArgonVariant == ARGON2I_VAR)
    {
      printf("Variant [Argon2i]");
    }
    else
    {
      printf("Variant [Argon2d]");
    }
    printf("\n\t");
    printf("Iterations [%d]", uiArgonIterations);
    printf("\n\t");
    printf("Threads [%d]", uiArgonThreads);
    printf("\n\t");
    printf("Memory [%llu MiB]\n", (((unsigned long long)(1) << ucArgonMemory) / 1024));

    printf("Deriving keys...\n");
    if (!deriveAesKeys(vSecretSequence, vSalt, vKey, vIv))
    {
      return false;
    }

    utils::memset_sec(&vSecretSequence[0], vSecretSequence.size(), bIsMemZeroed);
    if (!bIsMemZeroed)
    {
      printf("Warning: Argon2 passphrase area was not properly cleaned\n");
    }
  }

  printf("Encryption...\n");
  if (!utils::gcmEncryptFileWrap(sIn, sOut, vKey, vIv, ullProcessedBytes, vTag))
  {
    printf("Error occurred during encryption\n");
    return false;
  }

  if (ucKeyManagementOpt == AES_ENC_OPT_RSA)
  {
    const unsigned int rsaBuf = RSA_size(rsaKey);
    std::vector<unsigned char> vBufRSA(rsaBuf);

    vAppend.insert(vAppend.end(), vKey.begin(), vKey.end());
    vAppend.insert(vAppend.end(), vIv.begin(), vIv.end());
    if (!bDetachHeader)
    {
      vAppend.insert(vAppend.end(), vTag.begin(), vTag.end());
    }

    printf("RSA encryption...\n");
    const int rsaRetval = utils::encryptRsa(vAppend.size(), (unsigned char*)vAppend.data(), &vBufRSA[0], rsaKey);

    if (rsaRetval <= 0)
    {
      printf("RSA encryption failed\n");
      return false;
    }

    vAppend.clear();

    vAppend.insert(vAppend.end(), vBufRSA.begin(), vBufRSA.begin() + rsaRetval);

    vAppend.push_back((rsaRetval >> 8) & 0xff);
    vAppend.push_back(rsaRetval & 0xff);

    vAppend.push_back(AES_ENC_OPT_RSA);
  }
  else if (ucKeyManagementOpt == AES_ENC_OPT_KEY || ucKeyManagementOpt == AES_ENC_OPT_ECC)
  {
    if (!bDetachHeader)
    {
      vAppend.insert(vAppend.end(), vTag.begin(), vTag.end());
    }
    vAppend.push_back(ucArgonVariant);

    vAppend.push_back((uiArgonIterations >> 24) & 0xff);
    vAppend.push_back((uiArgonIterations >> 16) & 0xff);
    vAppend.push_back((uiArgonIterations >> 8) & 0xff);
    vAppend.push_back(uiArgonIterations & 0xff);

    vAppend.push_back((uiArgonThreads >> 24) & 0xff);
    vAppend.push_back((uiArgonThreads >> 16) & 0xff);
    vAppend.push_back((uiArgonThreads >> 8) & 0xff);
    vAppend.push_back(uiArgonThreads & 0xff);

    vAppend.push_back(ucArgonMemory);

    vAppend.insert(vAppend.end(), vSalt.begin(), vSalt.end());

    if (ucKeyManagementOpt == AES_ENC_OPT_ECC)
    {
      vAppend.insert(vAppend.end(), vEcEphemeral.begin(), vEcEphemeral.end());
    }

    ucKeyManagementOpt == AES_ENC_OPT_KEY ? vAppend.push_back(AES_ENC_OPT_KEY) : vAppend.push_back(AES_ENC_OPT_ECC);
  }

  bIsMemZeroed = false;
  utils::memset_sec(&vKey[0], vKey.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    printf("Warning: AES key memory area was not properly cleaned\n");
  }
 
  bIsMemZeroed = false;
  utils::memset_sec(&vIv[0], vIv.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    printf("Warning: AES iv memory area was not properly cleaned\n");
  }

  if (bDetachHeader)
  {
    if (!utils::WriteFile(sTag, vTag, O_CREAT | O_WRONLY))
    {
      printf("Could not write detached verification tag to file [%s]\n", sTag.c_str());
      return false;
    }

    vAppend.push_back(AES_ENC_OPT_TAG_DETACHED);
  }
  else
  {
    vAppend.push_back(AES_ENC_OPT_TAG_ATTACHED);
  }

  for (unsigned int i = 0; i < CERBERUS_SIGNATURE_SIZE; ++i)
  {
    vAppend.push_back(CERBERUS_FILE_SIGNATURE[i]);
  }

  if (!utils::WriteFile(sOut, vAppend, flagsWrite))
  {
    printf("Could not append metadata to encrypted file\n");
    return false;
  }

  return true;
}

bool Cerberus::_decryptFile()
{
  bool bIsMemZeroed = false;
  int fdIn = 0;
  const mode_t flagsRead = O_RDONLY | O_NOATIME;
  long long llFileSize = 0;
  long long llReadLimit = 0;
  unsigned long long ullProcessedBytes = 0;
  bool bIsTagDetached = false;
  unsigned char ucEncOpt = 0xff;
  std::vector<unsigned char> vKey, vIv, vAppend, vTmp, vTag;

  fdIn = utils::OpenFile(sIn, flagsRead, llFileSize);
  if (fdIn == -1)
  {
    printf("Error open input file [%s]\n", sIn.c_str());
    return false;
  }
  if (llFileSize <= AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE)
  {
    printf("Input file seems to be corrupted [%s]\n", sIn.c_str());
    utils::CloseFile(fdIn);
    return false;
  }

  vTmp.resize(CERBERUS_SIGNATURE_SIZE, 0);
  utils::SetSeekFileOffset(fdIn, llFileSize - CERBERUS_SIGNATURE_SIZE);

  if (utils::ReadFileChunk(fdIn, CERBERUS_SIGNATURE_SIZE, vTmp) != CERBERUS_SIGNATURE_SIZE)
  {
    printf("Error read signature [%s]\n", sIn.c_str());
    utils::CloseFile(fdIn);
    return false;
  }

  for (unsigned int i = 0; i < CERBERUS_SIGNATURE_SIZE; ++i)
  {
    if (CERBERUS_FILE_SIGNATURE[i] != vTmp[i])
    {
      printf("Signature is not found [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }
  }

  vTmp.resize(AES_TAG_OPCODE_SIZE, 0);
  utils::SetSeekFileOffset(fdIn, llFileSize - (AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE));

  if (utils::ReadFileChunk(fdIn, AES_TAG_OPCODE_SIZE, vTmp) != AES_TAG_OPCODE_SIZE)
  {
    printf("Error read tag metadata opcode [%s]\n", sIn.c_str());
    utils::CloseFile(fdIn);
    return false;
  }

  if (vTmp[0] != AES_ENC_OPT_TAG_DETACHED && vTmp[0] != AES_ENC_OPT_TAG_ATTACHED)
  {
    printf("Tag metadata opcode is invalid\n");
    utils::CloseFile(fdIn);
    return false;
  }

  bIsTagDetached = vTmp[0] == AES_ENC_OPT_TAG_DETACHED ? true : false;

  vTmp.resize(AES_KEY_OPCODE_SIZE, 0);
  utils::SetSeekFileOffset(fdIn, llFileSize - (AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE));

  if (utils::ReadFileChunk(fdIn, AES_KEY_OPCODE_SIZE, vTmp) != AES_KEY_OPCODE_SIZE)
  {
    printf("Error read key management metadata opcode [%s]\n", sIn.c_str());
    utils::CloseFile(fdIn);
    return false;
  }

  ucEncOpt = vTmp[0];

  if (ucEncOpt != AES_ENC_OPT_RSA && ucEncOpt != AES_ENC_OPT_KEY && ucEncOpt != AES_ENC_OPT_ECC)
  {
    printf("Key management metadata opcode is invalid\n");
    utils::CloseFile(fdIn);
    return false;
  }

  if (ucEncOpt == AES_ENC_OPT_RSA)
  {
    if (llFileSize <= RSA_METADATA_SIZE + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE)
    {
      printf("Input file seems to be corrupted [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }

    vTmp.resize(RSA_METADATA_SIZE, 0);
    utils::SetSeekFileOffset(fdIn, llFileSize - (RSA_METADATA_SIZE + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE));

    if (utils::ReadFileChunk(fdIn, RSA_METADATA_SIZE, vTmp) != RSA_METADATA_SIZE)
    {
      printf("Error read RSA metadata [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }

    unsigned short usRsaPayloadSize = vTmp[0];
    usRsaPayloadSize <<= 8;
    usRsaPayloadSize |= vTmp[1];

    if (llFileSize <= usRsaPayloadSize + RSA_METADATA_SIZE + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE)
    {
      printf("Input file seems to be corrupted [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }

    vTmp.resize(usRsaPayloadSize, 0);
    llReadLimit = llFileSize - (usRsaPayloadSize + RSA_METADATA_SIZE + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE);
    utils::SetSeekFileOffset(fdIn, llReadLimit);

    if (utils::ReadFileChunk(fdIn, usRsaPayloadSize, vTmp) != usRsaPayloadSize)
    {
      printf("Error read RSA payload [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }

    const unsigned int rsaBuf = RSA_size(rsaKey);
    const unsigned int payloadTagSize = bIsTagDetached ? 0 : TAG_SIZE;
    const std::vector<unsigned char> vRsaData = vTmp;
    vTmp.clear();
    vTmp.resize(rsaBuf, 0);

    printf("RSA decryption...\n");
    const int rsaRetval = utils::decryptRsa(vRsaData.size(), (unsigned char*)vRsaData.data(), &vTmp[0], rsaKey);

    if (rsaRetval != AES256_KEY_SIZE + IV_SIZE + payloadTagSize)
    {
      printf("Error decrypt RSA payload [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }

    vTmp.resize(rsaRetval);
    vKey.insert(vKey.end(), vTmp.begin(), vTmp.begin() + AES256_KEY_SIZE);
    vIv.insert(vIv.end(), vTmp.begin() + AES256_KEY_SIZE, vTmp.begin() + AES256_KEY_SIZE + IV_SIZE);
    if (!bIsTagDetached)
    {
      vTag.insert(vTag.end(), vTmp.begin() + AES256_KEY_SIZE + IV_SIZE, vTmp.end());
    }

  }
  else if (ucEncOpt == AES_ENC_OPT_KEY || ucEncOpt == AES_ENC_OPT_ECC)
  {
    // exclude tag size for now
    const unsigned int uiMetaSize = ucEncOpt == AES_ENC_OPT_KEY ? ARGON2_METADATA_SIZE : ECIES_METADATA_SIZE;

    if (llFileSize <= uiMetaSize + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE)
    {
      printf("Input file seems to be corrupted [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }

    vTmp.resize(uiMetaSize, 0);
    llReadLimit = llFileSize - (uiMetaSize + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE);
    utils::SetSeekFileOffset(fdIn, llReadLimit);

    if (utils::ReadFileChunk(fdIn, uiMetaSize, vTmp) != uiMetaSize)
    {
      printf("Error read Argon2 metadata [%s]\n", sIn.c_str());
      utils::CloseFile(fdIn);
      return false;
    }

    if (!bForce)
    {
      ucArgonVariant = vTmp[0];
      uiArgonIterations = utils::fillUnsignedInt(std::vector<unsigned char>(vTmp.begin() + 1, vTmp.begin() + 1 + 4));
      uiArgonThreads = utils::fillUnsignedInt(std::vector<unsigned char>(vTmp.begin() + 1 + 4, vTmp.begin() + 1 + 4 + 4));
      ucArgonMemory = vTmp[9];
    }

    std::vector<unsigned char> vSecretSequence, vSalt, vEcEphemeral;

    if (ucEncOpt == AES_ENC_OPT_KEY)
    {
      vSalt.insert(vSalt.end(), vTmp.begin() + (vTmp.size() - ARGON2_DEFAULT_SALT_SIZE), vTmp.end());
      vSecretSequence = vPassphraseBytes;
      vSecretSequence.insert(vSecretSequence.end(), vKeyFileBytes.begin(), vKeyFileBytes.end());
    }
    else
    {
      vSalt.insert(vSalt.end(), vTmp.begin() + (vTmp.size() - (ARGON2_DEFAULT_SALT_SIZE + EC_EPHEMERAL_KEY_PADDED_SIZE)), vTmp.end() - EC_EPHEMERAL_KEY_PADDED_SIZE);
      vEcEphemeral.insert(vEcEphemeral.end(), vTmp.begin() + (vTmp.size() - EC_EPHEMERAL_KEY_PADDED_SIZE), vTmp.end());
      vEcEphemeral.resize(vEcPub.size());

      if (!utils::eciesRXGenerateSymKey(ecKey, vEcEphemeral, vSecretSequence))
      {
        printf("Cannot generate RX shared key\n");
        return false;
      }

      printf("ECIES:");
      printf("\n\t");
      printf("Curve [%s]", utils::NID2Str(iEcGroup).c_str());
      printf("\n\t");
      printf("Affiliate point size [%lu]", vSecretSequence.size());
      printf("\n\t");
      printf("EC ephemeral key size [%lu]", vEcEphemeral.size());
      
      printf("\n\t");
      printf("\n");
    }

    if (!bIsTagDetached)
    {
      if (llFileSize <= TAG_SIZE + uiMetaSize + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE)
      {
        printf("Input file seems to be corrupted [%s]\n", sIn.c_str());
        utils::CloseFile(fdIn);
        return false;
      }

      vTmp.resize(TAG_SIZE, 0);
      llReadLimit = llFileSize - (TAG_SIZE + uiMetaSize + AES_KEY_OPCODE_SIZE + AES_TAG_OPCODE_SIZE + CERBERUS_SIGNATURE_SIZE);
      utils::SetSeekFileOffset(fdIn, llReadLimit);

      if (utils::ReadFileChunk(fdIn, TAG_SIZE, vTmp) != TAG_SIZE)
      {
        printf("Error read tag metadata [%s]\n", sIn.c_str());
        utils::CloseFile(fdIn);
        return false;
      }
      vTag = vTmp;
    }

    printf("Argon2 options:");
    printf("\n\t");
    if (ucArgonVariant == ARGON2ID_VAR)
    {
      printf("Variant [Argon2id]");
    }
    else if (ucArgonVariant == ARGON2I_VAR)
    {
      printf("Variant [Argon2i]");
    }
    else
    {
      printf("Variant [Argon2d]");
    }
    printf("\n\t");
    printf("Iterations [%d]", uiArgonIterations);
    printf("\n\t");
    printf("Threads [%d]", uiArgonThreads);
    printf("\n\t");
    printf("Memory [%llu MiB]\n", (((unsigned long long)(1) << ucArgonMemory) / 1024));

    printf("Deriving keys...\n");
    if (!deriveAesKeys(vSecretSequence, vSalt, vKey, vIv))
    {
      utils::CloseFile(fdIn);
      return false;
    }

    utils::memset_sec(&vSecretSequence[0], vSecretSequence.size(), bIsMemZeroed);
    if (!bIsMemZeroed)
    {
      printf("Warning: Argon2 passphrase area was not properly cleaned\n");
    }
  }

  utils::CloseFile(fdIn);

  if (bIsTagDetached && !bForce)
  {
    if (!utils::ReadFile(sTag, vTag))
    {
      printf("Could not read tag file [%s]\n", sTag.c_str());
      return false;
    }
  }

  printf("Decryption...\n");
  if (!utils::gcmDecryptFileWrap(sIn, sOut, vKey, vIv, vTag, llReadLimit, ullProcessedBytes, bForce))
  {
    return false;
  }

  bIsMemZeroed = false;
  utils::memset_sec(&vKey[0], vKey.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    printf("Warning: AES key memory area was not properly cleaned\n");
  }
 
  bIsMemZeroed = false;
  utils::memset_sec(&vIv[0], vIv.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    printf("Warning: AES iv memory area was not properly cleaned\n");
  }

  return true;
}

bool Cerberus::deriveAesKeys(const std::vector<unsigned char> &_vSecretSequence, const std::vector<unsigned char> &_vSalt, std::vector<unsigned char> &_vKey, std::vector<unsigned char> &_vIv)
{
  if (_vSecretSequence.empty() || _vSalt.empty())
  {
    printf("Passphrase and salt must be present\n");
    return false;
  }

  bool bIsMemZeroed = false;
  std::vector<unsigned char> vKeys(AES256_KEY_SIZE + IV_SIZE, 0);
  typedef bool FuncArgonVariant(unsigned char*, uint32_t, unsigned char*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, unsigned char*, unsigned char*, uint32_t);
  FuncArgonVariant *fArgonVariantPointer = NULL;

  if (ucArgonVariant == ARGON2ID_VAR)
  {
    fArgonVariantPointer = &utils::argon2id;
  }
  else if (ucArgonVariant == ARGON2I_VAR)
  {
    fArgonVariantPointer = &utils::argon2i;
  }
  else if (ucArgonVariant == ARGON2D_VAR)
  {
    fArgonVariantPointer = &utils::argon2d;
  }
  else
  {
    printf("Unknown Argon2 variant\n");
    return false;
  }

  if (!fArgonVariantPointer((unsigned char*)_vSecretSequence.data(), _vSecretSequence.size(), (unsigned char*)_vSalt.data(), _vSalt.size(),
      uiArgonIterations, (1 << ucArgonMemory), uiArgonThreads, vKeys.size(), &vKeys[0], NULL, 0))
  {
    printf("Argon2 internal error\n");
    return false;
  }

  _vKey = (std::vector<unsigned char>(vKeys.begin(), vKeys.begin() + AES256_KEY_SIZE));
  _vIv = (std::vector<unsigned char>(vKeys.begin() + AES256_KEY_SIZE, vKeys.end()));

  utils::memset_sec(&vKeys[0], vKeys.size(), bIsMemZeroed);
  if (!bIsMemZeroed)
  {
    printf("Warning: AES keys memory area was not properly cleaned\n");
  }

  return true;
}

