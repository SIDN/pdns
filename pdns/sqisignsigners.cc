extern "C"
{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <patad-testbed/sqisign1.h>
}
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"

class SQISign1DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit SQISign1DNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo)
  {}
  string getName() const override { return "SQISign-1"; }
  void create(unsigned int bits) override;

  [[nodiscard]] storvector_t convertToISCVector() const override;
  [[nodiscard]] std::string sign(const std::string& msg) const override;
  [[nodiscard]] bool verify(const std::string& msg, const std::string& signature) const override;
  [[nodiscard]] std::string getPublicKeyString() const override;
  [[nodiscard]] int getBits() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return make_unique<SQISign1DNSCryptoKeyEngine>(algorithm);
  }

private:
  unsigned char d_pubkey[SQISIGN1_PUBLICKEYBYTES];
  unsigned char d_seckey[SQISIGN1_SECRETKEYBYTES];
};

void SQISign1DNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits != (unsigned int)getBits()) {
    throw runtime_error("Unsupported key length of " + std::to_string(bits) + " bits requested, SQISign class");
  }
  sqisign_keypair(d_pubkey, d_seckey);
}

int SQISign1DNSCryptoKeyEngine::getBits() const
{
  return SQISIGN1_SECRETKEYBYTES << 3;
}

DNSCryptoKeyEngine::storvector_t SQISign1DNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvector;
  string algorithm = std::to_string(DNSSECKeeper::SQISIGN1) + " (SQISign-1)";

  storvector.emplace_back("Algorithm", algorithm);

  storvector.emplace_back("PrivateKey", string((char*)d_seckey, SQISIGN1_SECRETKEYBYTES));
  storvector.emplace_back("PublicKey", string((char*)d_pubkey, SQISIGN1_PUBLICKEYBYTES));
  return storvector;
}

void SQISign1DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);
  string publicKey = stormap["publickey"];
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != SQISIGN1_SECRETKEYBYTES)
    throw runtime_error("Private key size mismatch in ISCMap, SQISign class");

  if (publicKey.length() != SQISIGN1_PUBLICKEYBYTES)
    throw runtime_error("Public key size mismatch in ISCMap, SQISign class");

  memcpy(d_seckey, privateKey.c_str(), SQISIGN1_SECRETKEYBYTES);
  memcpy(d_pubkey, publicKey.c_str(), SQISIGN1_PUBLICKEYBYTES);
}

std::string SQISign1DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, SQISIGN1_PUBLICKEYBYTES);
}

void SQISign1DNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  if (input.length() != SQISIGN1_PUBLICKEYBYTES)
    throw runtime_error("Public key size mismatch, SQISign class");

  memcpy(d_pubkey, input.c_str(), SQISIGN1_PUBLICKEYBYTES);
}

std::mutex sqisign_sign_mutex; // XXX
std::string SQISign1DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  unsigned char combined[SQISIGN1_BYTES + msg.length()];
  unsigned long long combined_length;

  // XXX we need a mutex because when calling sqisign_sign concurrently, bad things happen.
  cerr << "SQISign sign: waiting for mutex" << endl;
  std::lock_guard<std::mutex> mutex(sqisign_sign_mutex);
  cerr << "SQISign sign: mutex released, signing" << endl;
  if (sqisign_sign(combined, &combined_length, (const unsigned char*)msg.c_str(), msg.length(), d_seckey) != 0) {
    throw runtime_error(getName() + " failed to generate signature");
  }
  cerr << "SQISign sign: signing done" << endl;

  return {(const char*)combined, combined_length - msg.length()};
}

bool SQISign1DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  return sqisign_verify((const unsigned char*)msg.c_str(), msg.length(), (const unsigned char*)signature.c_str(), signature.length(), d_pubkey) == 0;
}

namespace
{
const struct LoaderSQISignStruct
{
  LoaderSQISignStruct()
  {
    DNSCryptoKeyEngine::report(DNSSECKeeper::SQISIGN1, &SQISign1DNSCryptoKeyEngine::maker);
  }
} loadersqisign;
}
