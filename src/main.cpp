/*
 *
 *  Cerberus
 *  Created on: Dec 18, 2020
 *  Author: kernelp4n1c
 *  Build on: OpenSSL, Argon2
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>

#include "cerberus.hpp"

#define MAX_PWD_READ_LEN  4096

#define _HEADER_USAGE_  "Encryption: "                                                                                          \
                        "\n\t"                                                                                                  \
                        "cerberus --encrypt --in file.in --out file.out --ec-public ec_pub.pem --argon2-variant argon2d"        \
                        "\n\t"                                                                                                  \
                        "cerberus --encrypt --in file.in --out file.out --pwd --key-file file.key"                              \
                        "\n\n"                                                                                                  \
                        "Decryption: "                                                                                          \
                        "\n\t"                                                                                                  \
                        "cerberus --decrypt --in file.in --out file.out --rsa-private rsa_private.pem --key-file rsa_pem.pwd"   \
                        "\n\t"                                                                                                  \
                        "cerberus --decrypt --in file.in --out file.out --pwd"                                                  \
                        "\n\t"                                                                                                  \
                        "\n\n"                                                                                                  \
                        "Argon2 options:"                                                                                       \
                        "\n\t"                                                                                                  \
                        "--argon2-variant argon2i/argon2d/argon2id (default)"                                                   \
                        "\n\t"                                                                                                  \
                        "--iterations 1 to 2^32−1 (16 default)"                                                                 \
                        "\n\t"                                                                                                  \
                        "--threads 1 to 2^24−1 (degree of parallelism, 4 default)"                                              \
                        "\n\t"                                                                                                  \
                        "--memory 1 to 32 (memory usage of 2^N KiB, default 20)"                                                \
                        "\n\n\t"                                                                                                \
                        "Argon2 options are omitted with decryption process as those will be taken from encrypted "             \
                        "file metadata."                                                                                        \
                        "\n\t"                                                                                                  \
                        "In case any reason to force using other than stored values add --force flag"                           \
                        "\n\n"                                                                                                  \
                        "Attach/detach AES-GCM verification tag:"                                                               \
                        "\n\t"                                                                                                  \
                        "--tag file.tag"                                                                                        \
                        "\n\n\t"                                                                                                \
                        "Add --force flag in order to skip tag verification"                                                    \

void printHelp()
{
  printf("Cerberus v%s powered by kernelp4n1c (2025)\n\n", _CERBERUS_VERSION);
  printf("AES256-GCM encryption tool\n");
  printf("Keys management: RSA, Elliptic Curves (ECIES), Argon2\n");
  printf("Built against: OpenSSL, Argon2 shared libs\n");
  printf("\n");
  printf("%s\n", _HEADER_USAGE_);
  printf("\n\n");
  printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*");
  printf("\n");
  printf("Getting no message is also a message (c)*\n");
  printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*");
  printf("\n");
}

ssize_t getNoEchoLine(char *ucBufPtr, size_t *n)
{
  FILE* stream = stdin;
  struct termios old_term, new_term;
  ssize_t uiReaded = -1;

  if (tcgetattr(fileno(stream), &old_term) != 0)
  {
    return uiReaded;
  }

  new_term = old_term;
  new_term.c_lflag &= ~ECHO;

  if (tcsetattr(fileno(stream), TCSAFLUSH, &new_term) != 0)
  {
    return uiReaded;
  }

  uiReaded = getline(&ucBufPtr, n, stream);
  (void)tcsetattr(fileno(stream), TCSAFLUSH, &old_term);

  return uiReaded;
}

int main(int argc, char **argv)
{
  const std::string strParPrefix        = "--";
  const std::string strParEncrypt       = "encrypt";
  const std::string strParDecrypt       = "decrypt";
  const std::string strParIn            = "in";
  const std::string strParOut           = "out";
  const std::string strRsaPub           = "rsa-public";
  const std::string strRsaPriv          = "rsa-private";
  const std::string strEcPub            = "ec-public";
  const std::string strEcPriv           = "ec-private";
  const std::string strPwd              = "pwd";
  const std::string strKeyFile          = "key-file";
  const std::string strArgon2Variant    = "argon2-variant";
  const std::string strArgon2Iterations = "iterations";
  const std::string strArgon2Threads    = "threads";
  const std::string strArgon2Memory     = "memory";
  const std::string strTag              = "tag";
  const std::string strForce            = "force";

  const std::vector<std::string> vCmdOptions = {strParEncrypt, strParDecrypt, strParIn, strParOut, strRsaPub, strRsaPriv, strEcPub, strEcPriv, strPwd, strKeyFile,
    strArgon2Variant, strArgon2Iterations, strArgon2Threads, strArgon2Memory, strTag, strForce};

  bool bDirection   = false;
  bool bKeyOpt      = false;
  bool bIsEncrypt   = true;
  bool bIsRsa       = false;
  bool bIsEcc       = false;
  bool bIsPwd       = false;
  bool bIsKeyFile   = false;
  bool bIsTag       = false;
  bool bIsForce     = false;

  std::string strInputFilePath;
  std::string strOutputFilePath;
  std::string strRsaKeyFilePath;
  std::string strEcKeyFilePath;
  std::string strKeyFilePath;
  std::string strTagFilePath;

  RSA *rsaKey           = NULL;
  EC_KEY *ecKey         = NULL;
  bool bIsMemZeroed     = false;

  std::vector<unsigned char> vPassphrase, vKeyFile;

  unsigned char   ucArgonVariant      = ARGON2ID_VAR;
  unsigned int    uiArgonIterations   = ARGON2_DEFAULT_ITERATIONS;
  unsigned int    uiArgonThreads      = ARGON2_DEFAULT_THREADS;
  unsigned char   ucArgonMemory       = ARGON2_DEFAULT_MEM_DEGREE;

  for (int i = 0; i < argc; ++i)
  {
    if (std::string(argv[i]).find(strParPrefix) != 0)
    {
      continue;
    }
    else
    {
      bool bFound = false;
      for (const auto &opt : vCmdOptions)
      {
        if (std::string(argv[i]) == strParPrefix + opt)
        {
          bFound = true;
          break;
        }
      }
      if (!bFound)
      {
        printHelp();
        return argc;
      }
    }
    if (argv[i] == strParPrefix + strParEncrypt || argv[i] == strParPrefix + strParDecrypt)
    {
      if (bDirection)
      {
        printHelp();
        return argc;
      }
      if (argv[i] == strParPrefix + strParDecrypt)
      {
        bIsEncrypt = false;
      }
      bDirection = true;
      continue;
    }
    if (argv[i] == strParPrefix + strRsaPub || argv[i] == strParPrefix + strRsaPriv)
    {
      if (!bDirection || bKeyOpt)
      {
        printHelp();
        return argc;
      }
      if (argv[i] == strParPrefix + strRsaPub && !bIsEncrypt)
      {
        printHelp();
        return argc;
      }
      else if (argv[i] == strParPrefix + strRsaPriv && bIsEncrypt)
      {
        printHelp();
        return argc;
      }
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }
      bIsRsa = true;
      bKeyOpt = true;
      strRsaKeyFilePath = argv[i + 1];
      continue;
    }
    if (argv[i] == strParPrefix + strEcPub || argv[i] == strParPrefix + strEcPriv)
    {
      if (!bDirection || bKeyOpt)
      {
        printHelp();
        return argc;
      }
      if (argv[i] == strParPrefix + strEcPub && !bIsEncrypt)
      {
        printHelp();
        return argc;
      }
      else if (argv[i] == strParPrefix + strEcPriv && bIsEncrypt)
      {
        printHelp();
        return argc;
      }
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }
      bIsEcc = true;
      bKeyOpt = true;
      strEcKeyFilePath = argv[i + 1];
      continue;
    }
    if (argv[i] == strParPrefix + strPwd)
    {
      // pass to openssl layer
      if (bKeyOpt)
      {
        printHelp();
        return argc;
      }
      bIsPwd = true;
      bKeyOpt = true;
      continue;
    }
    if (argv[i] == strParPrefix + strKeyFile)
    {
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }
      bIsKeyFile = true;
      strKeyFilePath = argv[i + 1];
      continue;
    }
    if (argv[i] == strParPrefix + strParIn)
    {
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }
      strInputFilePath = argv[i + 1];
      continue;
    }
    if (argv[i] == strParPrefix + strParOut)
    {
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }
      strOutputFilePath = argv[i + 1];
      continue;
    }
    if (!bIsRsa && argv[i] == strParPrefix + strArgon2Variant)
    {
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }
      const std::string sVar = argv[i + 1];

      if (sVar == "argon2id")
      {
        ucArgonVariant = ARGON2ID_VAR;
      }
      else if (sVar == "argon2i")
      {
        ucArgonVariant = ARGON2I_VAR;
      }
      else if (sVar == "argon2d")
      {
        ucArgonVariant = ARGON2D_VAR;
      }
      else
      {
        printHelp();
        return argc;
      }
      continue;
    }
    if (!bIsRsa && argv[i] == strParPrefix + strArgon2Iterations || argv[i] == strParPrefix + strArgon2Threads || argv[i] == strParPrefix + strArgon2Memory)
    {
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }

      const std::string sTmp(argv[i + 1]);

      for (const auto &x : sTmp)
      {
        if (x < 0x30 || x > 0x39)
        {
          printHelp();
          return argc;
        }
      }

      const unsigned long long ullRetval = std::strtoull(sTmp.c_str(), NULL, 10);

      if (!ullRetval || ullRetval == ULLONG_MAX)
      {
        printHelp();
        return argc;
      }

      if (argv[i] == strParPrefix + strArgon2Iterations)
      {
        if (ullRetval > ((unsigned int)(1) << (32 - 1)))
        {
          printHelp();
          return argc;
        }
        uiArgonIterations = ullRetval;
      }
      else if (argv[i] == strParPrefix + strArgon2Threads)
      {
        if (ullRetval > (1 << (24 - 1)))
        {
          printHelp();
          return argc;
        }
        uiArgonThreads = ullRetval;
      }
      else if (argv[i] == strParPrefix + strArgon2Memory)
      {
        if (ullRetval > 32)
        {
          printHelp();
          return argc;
        }

        if (ullRetval >= 22)
        {
          printf("Proceed using [%llu GiB] memory? (y/n)\n", (((unsigned long long)(1) << ullRetval) / 1024 / 1024));
          char c = getchar();
          if (c != 'y' && c != 'Y')
          {
            printf("Aborted\n");
            return argc;
          }
        }
        ucArgonMemory = ullRetval;
      }
      continue;
    }
    if (argv[i] == strParPrefix + strTag)
    {
      if (i + 1 > argc)
      {
        printHelp();
        return argc;
      }
      bIsTag = true;
      strTagFilePath = argv[i + 1];
      continue;
    }
    if (argv[i] == strParPrefix + strForce)
    {
      bIsForce = true;
    }
  }

  if (!bDirection || !bKeyOpt || strInputFilePath.empty() || strOutputFilePath.empty())
  {
    printHelp();
    return argc;
  }

  if (utils::IsFileExist(strInputFilePath) == false)
  {
    printf("Input file not found\n");
    return -1;
  }
  if (utils::IsFileExist(strOutputFilePath))
  {
    printf("Output file already exist\n");
    return -1;
  }

  if (bIsKeyFile)
  {
    if (utils::IsFileExist(strKeyFilePath) == false)
    {
      printf("Key file not found\n");
      return -1;
    }
    const unsigned long long ullKeyFileSize = utils::GetFileSize(strKeyFilePath);
    if (ullKeyFileSize > _MAX_KEY_FILE_SIZE)
    {
      printf("Key file is too large\n");
      return -1;
    }
    if (utils::ReadFile(strKeyFilePath, vKeyFile, ullKeyFileSize) == false)
    {
      printf("Cannot read key file\n");
      return -1;
    }
    if (vKeyFile.empty())
    {
      printf("Key file is empty\n");
      return -1;
    }
  }

  if (bIsRsa)
  {
    if (utils::IsFileExist(strRsaKeyFilePath) == false)
    {
      printf("RSA key file not found\n");
      return -1;
    }

    if (bIsEncrypt)
    {
      rsaKey = utils::getPubRSA(strRsaKeyFilePath);
      if (rsaKey == NULL)
      {
        printf("RSA public key is not valid\n");
        return -1;
      }
    }
    else
    {
      if (vKeyFile.empty())
      {
        rsaKey = utils::getPrivRSA(strRsaKeyFilePath);
      }
      else
      {
        rsaKey = utils::getPrivRSA(strRsaKeyFilePath, &vKeyFile[0]);
      }
      if (rsaKey == NULL)
      {
        printf("RSA private key is not valid\n");
        return -1;
      }
    }
  }
  else if (bIsEcc)
  {
    if (utils::IsFileExist(strEcKeyFilePath) == false)
    {
      printf("EC key file not found\n");
      return -1;
    }

    if (bIsEncrypt)
    {
      ecKey = utils::getPubEC(strEcKeyFilePath);
      if (ecKey == NULL)
      {
        printf("EC public key is not valid\n");
        return -1;
      }
    }
    else
    {
      if (vKeyFile.empty())
      {
        ecKey = utils::getPrivEC(strEcKeyFilePath);
      }
      else
      {
        ecKey = utils::getPrivEC(strEcKeyFilePath, &vKeyFile[0]);
      }
      if (ecKey == NULL)
      {
        printf("EC private key is not valid\n");
        return -1;
      }
    }
  }
  else if (bIsPwd)
  {
    size_t uiMaxPwdLen = MAX_PWD_READ_LEN;
    unsigned char *ucPtr = NULL;

    ucPtr = (unsigned char*)malloc(uiMaxPwdLen);
    if (ucPtr == NULL)
    {
      printf("Could not allocate memory for passphrase reading\n");
      return -1;
    }

    memset(ucPtr, 0, uiMaxPwdLen);

    printf("Input passphrase: ");
    ssize_t uiRetval = getNoEchoLine((char*)ucPtr, &uiMaxPwdLen);
    printf("\n");

    if (uiRetval == -1 || uiRetval <= 1)
    {
      printf("Could not read password from stdin\n");
      return -1;
    }
    if (uiRetval - 1 > MAX_PWD_READ_LEN)
    {
      printf("Passphrase too large\n");
      return -1;
    }

    vPassphrase.resize(uiRetval - 1, 0);
    memcpy(&vPassphrase[0], ucPtr, uiRetval - 1);

    if (bIsEncrypt)
    {
      memset(ucPtr, 0, uiMaxPwdLen);

      printf("Confirm passphrase: ");
      uiRetval = getNoEchoLine((char*)ucPtr, &uiMaxPwdLen);
      printf("\n");

      if (uiRetval == -1 || uiRetval <= 1)
      {
        printf("Could not read password from stdin\n");
        return -1;
      }

      if (vPassphrase.size() != uiRetval - 1 || memcmp(&vPassphrase[0], ucPtr, vPassphrase.size()) != 0)
      {
        printf("Passphrases do not match\n");
        return -1;
      }
    }

    if (ucPtr)
    {
      utils::memset_sec(ucPtr, uiMaxPwdLen, bIsMemZeroed);
      if (!bIsMemZeroed)
      {
        printf("Warning: passphrase memory area was not properly cleaned\n");
      }
      free(ucPtr);
    }
  }
  else
  {
    printHelp();
    return -1;
  }

  Cerberus cerberObj(strInputFilePath, strOutputFilePath);
  cerberObj.setArgonParams(ucArgonVariant, uiArgonIterations, uiArgonThreads, ucArgonMemory);

  if (bIsTag)
  {
    if (!bIsEncrypt)
    {
      if (utils::IsFileExist(strTagFilePath) == false)
      {
        printf("Tag file not found\n");
        return -1;
      }
    }
    cerberObj.detachTag(strTagFilePath);
  }

  if (bIsRsa)
  {
    cerberObj.setRsaKey(rsaKey);
    cerberObj.processWithRsa();
  }
  else if (bIsEcc)
  {
    if (!cerberObj.setEcKey(ecKey))
    {
      printf("Cannot load EC key\n");
      return -1;
    }
    cerberObj.processWithEcc();
  }
  else if (bIsPwd || bIsKeyFile)
  {
    cerberObj.setPassphrase(vPassphrase);
    cerberObj.setKeyFileData(vKeyFile);
    cerberObj.processWithKeys();
  }

  if (bIsForce)
  {
    cerberObj.setForce();
  }

  if (bIsEncrypt)
  {
    if (cerberObj.encryptFile() == false)
    {
      printf("Error during encryption\n");
      return -1;
    }
  }
  else
  {
    if (cerberObj.decryptFile() == false)
    {
      if (utils::IsFileExist(strOutputFilePath))
      {
        unlink(strOutputFilePath.c_str());
      }
      printf("Error during decryption\n");
      return -1;
    }
  }

  // TODO: work with memory
  cerberObj.reset();
  if (rsaKey)
  {
//    RSA_free(rsaKey);
  }
  if (ecKey)
  {
//    EC_KEY_free(ecKey);
  }

  bIsMemZeroed = false;
  if (!vPassphrase.empty())
  {
    utils::memset_sec(&vPassphrase[0], vPassphrase.size(), bIsMemZeroed);
    if (!bIsMemZeroed)
    {
      printf("Warning: passphrase memory area was not properly cleaned\n");
    }
    vPassphrase.clear();
  }

  bIsMemZeroed = false;
  if (!vKeyFile.empty())
  {
    utils::memset_sec(&vKeyFile[0], vKeyFile.size(), bIsMemZeroed);
    if (!bIsMemZeroed)
    {
      printf("Warning: key file memory area was not properly cleaned\n");
    }
    vKeyFile.clear();
  }

  printf("\n* File [%s] is %s and saved to [%s]\n", strInputFilePath.c_str(), bIsEncrypt ? "encrypted" : "decrypted", strOutputFilePath.c_str());

  return 0;
}

