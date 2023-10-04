#include "config.h"
#include "macros.h"
#include "sodium.h"
#include <iostream>
#include <sodium/crypto_pwhash.h>
#include <string>

// psf::lock provides functions for encrypting and decrypting data
namespace psf::lock {
  /**
   * Invokes libsodium's "randombytes_buf" function, this is just an
   * alias for readability.
   */
  inline void
  generate_nonce(unsigned char* out, const unsigned int& nonce_size) {
    randombytes_buf(out, nonce_size);
  }

  /**
   * Invokes libsodium's "randombytes_buf" function, this is just an
   * alias or readability.
   */
  inline void
  generate_salt(unsigned char* out, const unsigned int& salt_size) {
    randombytes_buf(out, salt_size);
  }

  inline void derivate_key(
      unsigned char* out,
      unsigned char* salt,
      const std::string& pwd,
      const unsigned int& salt_size = SALT_SIZE,
      const unsigned int& key_size = KEY_SIZE
  ) {
    // We define an alias to "out" as "key" for readability
    unsigned char*& key = out;

    psf::lock::generate_salt(salt, salt_size);

    /**
     * The key should ideally be stored safely after generation,
     * preferably nowhere to be found
     */
    if ((crypto_pwhash(
            key,
            key_size,
            pwd.c_str(),
            pwd.length(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT
        )) != 0) {
      std::cerr << "Unable to derive key." << std::endl;
    }
  }

  /*
   * Encrypts a file using a password
   */
  void encrypt_file(
      psf::config& config,
      const std::string& file_path,
      const std::string& output_path,
      const std::string& pwd
  );

  /*
   * Decrypts a file using a password
   */
  void decrypt_file(
      psf::config& config,
      const std::string& file_path,
      const std::string& output_path,
      const std::string& pwd
  );
} // namespace psf::lock
