namespace psf {
  class config {
  public:
    config(
        const unsigned int _salt_size,
        const unsigned int _nonce_size,
        const unsigned int _key_size
    )
        : salt_size(_salt_size), nonce_size(_nonce_size),
          key_size(_key_size) {}

    const unsigned int salt_size;
    const unsigned int nonce_size;
    const unsigned int key_size;
  };
} // namespace psf
