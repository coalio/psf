#include "lock.h"
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

void psf::lock::encrypt_file(
    psf::config& config,
    const std::string& file_path,
    const std::string& output_path,
    const std::string& pwd
) {
  // Let's get the key, salt and nonce size from the config
  unsigned int key_size = config.key_size;
  unsigned int salt_size = config.salt_size;
  unsigned int nonce_size = config.nonce_size;

  auto key = new unsigned char[key_size];
  auto salt = new unsigned char[salt_size];
  derivate_key(key, salt, pwd);

  auto nonce = new unsigned char[nonce_size];
  generate_nonce(nonce, nonce_size);

  std::ifstream input_file(file_path, std::ios::binary);
  if (!input_file) {
    std::cerr << "[" << file_path << "] unable to open" << std::endl;
    return;
  }

  // Let's get the input file size, and sum the salt and nonce size to
  // it, then reserve some space for the final data

  input_file.seekg(0, std::ios::end);
  std::streampos file_size = input_file.tellg();
  input_file.seekg(0, std::ios::beg);

  if (file_size == -1) {
    std::cerr << "[" << file_path << "] error getting file size"
              << std::endl;
    return;
  } else if (file_size == 0) {
    std::cerr << "[" << file_path << "] ignoring empty file"
              << std::endl;
    return;
  }

  // Temporarily rename output file to a .lock extension, to prevent a
  // collision or loss of data
  auto temp_path = output_path + ".lock";
  if (fs::exists(temp_path)) {
    std::cerr << "[" << file_path
              << "] unable to lock unless the .lock version of this "
                 "file is deleted. ("
              << temp_path << ")" << std::endl;
    return;
  }

  std::ofstream temp_file(temp_path, std::ios::binary);
  if (!temp_file) {
    std::cerr << "[" << file_path << "] failed to create temp file"
              << std::endl;
    return;
  }

  temp_file.write(reinterpret_cast<char*>(salt), salt_size);
  temp_file.write(reinterpret_cast<char*>(nonce), nonce_size);

  unsigned char buffer[1024];

  while (!input_file.eof()) {
    input_file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
    size_t bytes_read = static_cast<size_t>(input_file.gcount());
    unsigned char ciphertext[bytes_read + crypto_secretbox_MACBYTES];

    // Encrypt the buffer
    if (crypto_secretbox_easy(
            ciphertext, buffer, bytes_read, nonce, key
        ) != 0) {
      std::cerr << "[" << file_path << "] failed" << std::endl;

      // Close the temp file and remove it
      temp_file.close();
      fs::remove(temp_path);

      return;
    }

    // Write the ciphertext to the temp file
    temp_file.write(
        reinterpret_cast<char*>(ciphertext), sizeof(ciphertext)
    );
  }

  input_file.close();
  temp_file.close();

  // Let's now rename the temp file
  if (fs::exists(output_path)) {
    fs::remove(output_path);
  }

  fs::rename(temp_path, output_path);

  // Let's free the memory
  delete[] key;
  delete[] salt;
  delete[] nonce;
};

void psf::lock::decrypt_file(
    psf::config& config,
    const std::string& file_path,
    const std::string& output_path,
    const std::string& pwd
) {
  unsigned int key_size = config.key_size;
  unsigned int salt_size = config.salt_size;
  unsigned int nonce_size = config.nonce_size;

  unsigned char key[key_size];
  unsigned char nonce[nonce_size];
  unsigned char salt[salt_size];

  // Open the input file
  std::ifstream input_file(file_path, std::ios::binary);
  if (!input_file) {
    std::cerr << "[" << file_path << "] unable to open" << std::endl;
    return;
  }

  // Read the salt and nonce from the beginning of the input file
  input_file.read(reinterpret_cast<char*>(salt), salt_size);
  input_file.read(reinterpret_cast<char*>(nonce), nonce_size);

  // Derive the key from the password and salt
  if (crypto_pwhash(
          key,
          KEY_SIZE,
          pwd.c_str(),
          pwd.length(),
          salt,
          crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE,
          crypto_pwhash_ALG_DEFAULT
      ) != 0) {
    std::cerr << "key derivation failed" << std::endl;
    return;
  }

  // Temporarily rename output file to a .lock extension, to prevent a
  // collision or loss of data
  auto temp_path = output_path + ".lock";
  if (fs::exists(temp_path)) {
    std::cerr << "[" << file_path
              << "] unable to lock unless the .lock version of this "
                 "file is deleted. ("
              << temp_path << ")" << std::endl;
    return;
  }

  std::ofstream temp_file(temp_path, std::ios::binary);
  if (!temp_file) {
    std::cerr << "[" << file_path << "] failed to create temp file"
              << std::endl;
    return;
  }

  // Decrypt and write the file contents
  unsigned char buffer[1024];

  while (!input_file.eof()) {
    input_file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
    size_t bytes_read = static_cast<size_t>(input_file.gcount());
    unsigned char plaintext[bytes_read - crypto_secretbox_MACBYTES];

    if (crypto_secretbox_open_easy(
            plaintext, buffer, bytes_read, nonce, key
        ) != 0) {
      std::cerr << "[" << file_path << "] failed during decryption"
                << std::endl;

      // Close the temp file and remove it
      temp_file.close();
      fs::remove(temp_path);

      return;
    }

    // Write the plaintext to the temp file
    temp_file.write(
        reinterpret_cast<char*>(plaintext), sizeof(plaintext)
    );
  }

  // Close the files
  input_file.close();
  temp_file.close();

  // Now we can rename the temp file to the intended output path
  if (fs::exists(output_path)) {
    fs::remove(output_path);
  }

  fs::rename(temp_path, output_path);
}
