#include <iostream>
#include <random>

#include "main.hxx"

#include <picosha2.h>
#include <gsl/gsl>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    Usage(argv[0]);
    return 1;
  }

  int const numOfWords = std::atoi(argv[1]);
  if (numOfWords < 1 || numOfWords > sizeof(Words) / sizeof(Words[0])) {
    Usage(argv[0]);
    return 2;
  }

  std::cout << "Acknowledges:\n"
            << " * SHA256 library: https://github.com/okdshin/PicoSHA2\n"
            << " * GSL:            https://github.com/Microsoft/GSL\n";
  
  char const *wallet = Wallets[numOfWords - 1];
  std::cout << "Starting on " << wallet << '\n';
  std::cout << numOfWords << " word passphrase" << '\n';

  {
    int wordIndices[numOfWords];

    std::array<unsigned char, 32> hash;
    picosha2::hash256_one_by_one hasher;

    std::random_device rd;  // will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> dis(0, sizeof(Words) / sizeof(Words[0]) - 1);

    for (int i = 0; i < numOfWords; ++i) {
      auto const wordIndex = dis(gen);
      auto const &word = Words[wordIndex];

      hasher.process(word.cbegin(), word.cend());
      hasher.process(Whitespace.cbegin(), Whitespace.cend());

      // std::cout << gsl::to_string(word) << ' ';
    }
    hasher.finish();
    // std::cout << '\n';

    hasher.get_hash_bytes(hash.begin(), hash.end());
    
    std::cout << "hash= " << picosha2::get_hash_hex_string(hasher) << '\n';
  }
  
  return 0;
}

void Usage(char const *progname) {
  std::cout << "Usage: " << progname << " <1..12>" << std::endl;
}
