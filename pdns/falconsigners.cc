extern "C"
{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <patad-testbed/falcon512.h>
}
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"

class Falcon512DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit Falcon512DNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo)
  {}
  string getName() const override { return "Falcon-512"; }
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
    return make_unique<Falcon512DNSCryptoKeyEngine>(algorithm);
  }

private:
  unsigned char d_pubkey[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
  unsigned char d_seckey[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
};

void Falcon512DNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits != (unsigned int)getBits()) {
    throw runtime_error("Unsupported key length of " + std::to_string(bits) + " bits requested, Falcon512 class");
  }
  PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(d_pubkey, d_seckey);
}

int Falcon512DNSCryptoKeyEngine::getBits() const
{
  return PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES << 3;
}

DNSCryptoKeyEngine::storvector_t Falcon512DNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvector;
  string algorithm = std::to_string(DNSSECKeeper::FALCON512) + " (Falcon-512)";

  storvector.emplace_back("Algorithm", algorithm);

  storvector.emplace_back("PrivateKey", string((char*)d_seckey, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES));
  storvector.emplace_back("PublicKey", string((char*)d_pubkey, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES));
  return storvector;
}

void Falcon512DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);
  string publicKey = stormap["publickey"];
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES)
    throw runtime_error("Private key size mismatch in ISCMap, Falcon512 class");

  if (publicKey.length() != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES)
    throw runtime_error("Public key size mismatch in ISCMap, Falcon512 class");

  memcpy(d_seckey, privateKey.c_str(), PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES);
  memcpy(d_pubkey, publicKey.c_str(), PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
}

std::string Falcon512DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
}

void Falcon512DNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  if (input.length() != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES)
    throw runtime_error("Public key size mismatch, Falcon512 class");

  memcpy(d_pubkey, input.c_str(), PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
}

std::string Falcon512DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  unsigned char signature[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
  size_t signature_length;

  if (PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(signature, &signature_length, (const unsigned char*)msg.c_str(), msg.length(), d_seckey) != 0) {
    throw runtime_error(getName() + " failed to generate signature");
  }

  return {(const char*)signature, signature_length};
}

bool Falcon512DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify((const unsigned char*)signature.c_str(), signature.length(), (const unsigned char*)msg.c_str(), msg.length(), d_pubkey) == 0;
}

namespace
{
const struct LoaderFalconStruct
{
  LoaderFalconStruct()
  {
    DNSCryptoKeyEngine::report(DNSSECKeeper::FALCON512, &Falcon512DNSCryptoKeyEngine::maker);
  }
} loaderfalcon;
}
