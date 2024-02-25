#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#include "arg.h"
#include "lock.h"
#include "macros.h"

namespace fs = std::filesystem;

auto help_message() {
  std::cout << "usage:"
               "\n"
            << "\tpsf { [-l | -u ] <pwd> | -h }"
               "\n\n"
            << "\t-l : lock the workdir folder"
               "\n"
            << "\t-u : unlock the workdir folder"
               "\n"
            << "\t-h : show this message"
               "\n\n"
            << "\t<pwd> : the password"
               "\n\n"
            << "example:"
               "\n"
            << "\tpsf -l 123456"
               "\n"
            << "\tpsf -u 123456"
               "\n"
            << "\tpsf -h"
               "\n";
}

auto main(int argc, char* argv[]) -> int {
  if (sodium_init() < 0) {
    // panic! the library couldn't be initialized, so it's unsafe to
    // use
    std::cerr << "panic! libsodium failed to initialize."
              << std::endl;
    return 1;
  }

  std::cout << "psf " VERSION " - " REPO << "\n";
  std::cout << DESCRIPTION ", written with <3 by " AUTHOR
            << std::endl;

  // TODO: This probably should be loaded from a toml file in a global
  // place
  auto conf = psf::config(105, 105, 1024);

  if (!argc) {
    help_message();
  }

  arg::arg_list args;

  try {
    args = arg::parse(argc, argv);
  } catch (std::runtime_error e) {
    std::cout << e.what() << std::endl;
    help_message();

    return 1;
  }

  if (args.empty()) {
    help_message();

    return 1;
  }

  if (arg::has(args, "h")) {
    help_message();

    return 1;
  }

  if (arg::has(args, "l")) {
    std::string pwd = arg::get(args, "l");

    if (pwd.empty() || pwd.at(0) == 1) {
      std::cerr << "no password provided, quitting" << std::endl;

      return 1;
    }

    for (const auto& entry :
         fs::recursive_directory_iterator(fs::current_path())) {
      // Regular files are encrypted in-place, and directories are
      // traversed recursively
      if (!entry.path().string().ends_with(".lock") &&
          entry.is_regular_file()) {
        // Attempt encrypting this file on top of itself
        psf::lock::encrypt_file(
            conf, entry.path(), entry.path(), pwd
        );
      }
    }
  }

  if (arg::has(args, "u")) {
    std::string pwd = arg::get(args, "u");

    if (pwd.empty() || pwd.at(0) == 1) {
      std::cerr << "no password provided, quitting" << std::endl;

      return 1;
    }

    for (const auto& entry :
         fs::recursive_directory_iterator(fs::current_path())) {
      if (!entry.path().string().ends_with(".lock") &&
          entry.is_regular_file()) {
        psf::lock::decrypt_file(
            conf, entry.path(), entry.path(), pwd
        );
      }
    }
  }

  return 0;
}
