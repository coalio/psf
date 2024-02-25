#define VERSION "0.1.0"
#define AUTHOR "coal"
#define REPO "https://github.com/coalio/psf"
#define DESCRIPTION "Enables authentication for folders"

// The encryption key size
#define KEY_SIZE crypto_secretbox_KEYBYTES

// The nonce size
#define NONCE_SIZE crypto_secretbox_NONCEBYTES

// The salt size
#define SALT_SIZE crypto_pwhash_SALTBYTES

// The buffer size
#define BUFFSIZE 4096

// The defined options, this is later reconstructed to a vector when
// required
#define VALID_OPTIONS                                                \
  { "l", "u", "h" }
