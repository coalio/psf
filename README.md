## psf: the local folder authenticator

`psf` provides security to your sensitive data by providing locking capabilities for entire folders.

It watches for open file descriptors in the folder. When the folder contents are no longer in use, `psf` encrypts it again, automatically.

## Getting started

`psf` depends in [libsodium](https://github.com/jedisct1/libsodium), a cryptography library that powers `psf`.

Common procedure (assuming all dependencies were fulfilled):

```
git clone https://github.com/coalio/psf
cd psf
mkdir build && cd build
cmake ..
make
sudo make install
```
