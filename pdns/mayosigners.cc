extern "C"
{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#define MAYO_VARIANT MAYO_2
#define ENABLE_PARAMS_DYNAMIC
#include <patad-testbed/mayo-build-type.h>
#include <patad-testbed/mayo.h>
}
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"

class MAYO2DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit MAYO2DNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo)
  {}
  string getName() const override { return "MAYO-2"; }
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
    return make_unique<MAYO2DNSCryptoKeyEngine>(algorithm);
  }

private:
  unsigned char d_pubkey[MAYO_2_cpk_bytes];
  unsigned char d_seckey[MAYO_2_csk_bytes];
};

void MAYO2DNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits != (unsigned int)getBits()) {
    throw runtime_error("Unsupported key length of " + std::to_string(bits) + " bits requested, MAYO2 class");
  }
  mayo_keypair(0, d_pubkey, d_seckey);
}

int MAYO2DNSCryptoKeyEngine::getBits() const
{
  return MAYO_2_csk_bytes << 3;
}

DNSCryptoKeyEngine::storvector_t MAYO2DNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvector;
  string algorithm = std::to_string(DNSSECKeeper::MAYO2) + " (MAYO-2)";

  storvector.emplace_back("Algorithm", algorithm);

  storvector.emplace_back("PrivateKey", string((char*)d_seckey, MAYO_2_csk_bytes));
  storvector.emplace_back("PublicKey", string((char*)d_pubkey, MAYO_2_cpk_bytes));
  return storvector;
}

void MAYO2DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);
  string publicKey = stormap["publickey"];
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != MAYO_2_csk_bytes)
    throw runtime_error("Private key size mismatch in ISCMap, MAYO2 class");

  if (publicKey.length() != MAYO_2_cpk_bytes)
    throw runtime_error("Public key size mismatch in ISCMap, MAYO2 class");

  memcpy(d_seckey, privateKey.c_str(), MAYO_2_csk_bytes);
  memcpy(d_pubkey, publicKey.c_str(), MAYO_2_cpk_bytes);
}

std::string MAYO2DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, MAYO_2_cpk_bytes);
}

void MAYO2DNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  if (input.length() != MAYO_2_cpk_bytes)
    throw runtime_error("Public key size mismatch, MAYO2 class");

  memcpy(d_pubkey, input.c_str(), MAYO_2_cpk_bytes);
}

std::string MAYO2DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  size_t signature_length;
  unsigned char signature[MAYO_2_sig_bytes];

  if (mayo_sign_signature(0, signature, &signature_length, (const unsigned char*)msg.c_str(), msg.length(), d_seckey) != 0) {
    throw runtime_error(getName() + " failed to generate signature");
  }

  return {(const char*)signature, signature_length};
}

bool MAYO2DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  return mayo_verify(0, (const unsigned char*)msg.c_str(), msg.length(), (const unsigned char*)signature.c_str(), d_pubkey) == 0;
}

namespace
{
const struct LoaderMAYOStruct
{
  LoaderMAYOStruct()
  {
    DNSCryptoKeyEngine::report(DNSSECKeeper::MAYO2, &MAYO2DNSCryptoKeyEngine::maker);
  }
} loadermean;
}
