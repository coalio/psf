#include "arg.h"
#include <stdexcept>

auto arg::parse(int argc, char** argv) -> arg_list {
  arg_list args{};

  // Parse the arguments and return the args map
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg[0] == '-') {
      std::string name = arg.substr(1, arg.length() - 1);

      if (!arg::is_valid_option(name)) {
        throw std::runtime_error(
            (name + " is not a valid option").c_str()
        );
      }

      if (i + 1 < argc && argv[i + 1][0] != '-') {
        std::string value = argv[i + 1];
        args[name] = value;
        i++;
      } else {
        args[name] = 1;
      }
    }
  }

  return args;
}

auto arg::get(arg_list args, std::string name) -> std::string {
  if (args.find(name) != args.end()) {
    return args[name];
  } else {
    return "";
  }
}

auto arg::has(arg_list args, std::string name) -> bool {
  return args.find(name) != args.end();
}

