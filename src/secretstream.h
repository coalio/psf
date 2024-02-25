#include "macros.h"
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <streambuf>
#include <string>

// Ok I understand C doesn't have namespaces but seriously?
#define secretstream(S) crypto_secretstream_xchacha20poly1305_##S

namespace psf {
  // I'm sorry, please suggest better names for this class
  class sxpstream : public std::basic_streambuf<unsigned char> {
  public:
    // The size of the buffer
    static const unsigned int SECRETSTREAM_BUFFSIZE =
        BUFFSIZE + secretstream(ABYTES);

    // The size of the header
    static const unsigned int HEADERBYTES = secretstream(HEADERBYTES);

    sxpstream() = delete;

    sxpstream(unsigned char* _key) : key(_key) {
      this->setp(buffer, buffer + SECRETSTREAM_BUFFSIZE);
      this->setg(buffer, buffer, buffer + SECRETSTREAM_BUFFSIZE);
    }

    /*
     * The key to use when encrypting the stream.
     * If you wish to *forget* the key and use a new one mid stream,
     * use set_key(unsigned char& key)
     */
    unsigned char* key;

    /*
     * The buffer. This is filled temporarily while
     * encrypting/decrypting streams.
     */
    unsigned char buffer[SECRETSTREAM_BUFFSIZE];

    /*
     * The header.
     */
    unsigned char header[HEADERBYTES];

    /*
     * The stream state. The function macro is convenient for
     * shortening the huge C prefix.
     */
    secretstream(state) * st;

    inline auto init_push() -> void {
      secretstream(init_push)(this->st, this->header, this->key);
    }

    /*
     * overflow ensures that there's enough space for at least one
     * miserable char
     */
    int_type overflow(int_type ch) override {
      if (ch != traits_type::eof()) {
        // Check if the put pointer is at the end already
        if (pptr() != epptr()) {
          // If not, write to it and move it to the next place
          *pptr() = ch;
          pbump(1);

          return ch;
        }
      }

      // We're full
      return traits_type::eof();
    }

    /*
     * The opposite, it checks if our source has information
     */
    int_type underflow() override {
      // The same thing, we return the character at the get position
      // if not empty
      if (gptr() < egptr()) {
        return traits_type::to_int_type(*gptr());
      }

      // We're done reading the source
      return traits_type::eof();
    }
  };
} // namespace psf
