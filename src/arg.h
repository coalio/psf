#include "macros.h"
#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace arg {
  /*
   * A vector containing only supported options
   */
  static std::vector<std::string> options = VALID_OPTIONS;

  /*
   * A type used to alias the vector resulting from argument parsing
   */
  typedef std::unordered_map<std::string, std::string> arg_list;

  /*
   * Checks whether the option name found in the command is valid
   */
  inline auto is_valid_option(std::string option_name) -> bool {
    auto p = std::find(options.begin(), options.end(), option_name);
    return p != options.end();
  };

  /*
   * Returns a list of arguments from the given argc and argv
   */
  auto parse(int argc, char** argv) -> arg_list;

  /*
   * Returns the value of the given argument
   */
  auto get(arg_list args, std::string key) -> std::string;

  /*
   * Returns true if the given argument is present
   */
  auto has(arg_list args, std::string name) -> bool;

} // namespace arg
