#include <algorithm>
#include <atomic>
#include <chrono>
#include <forward_list>
#include <functional>
#include <iostream>
#include <mutex>
#include <random>
#include <thread>

#include "main.hxx"
#include "utils.hxx"

#include <gsl/gsl>
#include <picosha2.h>
#include <pthread.h>
#include <rfc7748_precompted.h>

struct Hashing {
  struct Stats {
    std::size_t tries{0};
    std::chrono::duration<double> elapsedTime{0};
  };

  Hashing(unsigned nWords)
      : nWords_(nWords)
  {}
  Hashing(Hashing const &other) = delete;
  Hashing(Hashing&& other)
      : nWords_(other.nWords_), stats_(other.stats_)
  {}

  void operator () (std::mutex &printingMutex, std::atomic_bool &isDone) {
    PROFILE(
        std::chrono::duration<double> shaTime{0};
        std::chrono::duration<double> curveTime{0};
    )

    std::random_device              rd;
    std::default_random_engine      gen(rd());
    std::uniform_int_distribution<> dis(0, DictSize - 1);

    bool hit = false;
    int  wordIndices[nWords_];
    std::array<unsigned char, 32> secretKey;
    std::array<unsigned char, 32> publicKey;
    auto const &publicKeyReference = PublicKeys[nWords_ - 1];

    auto const startedAt = std::chrono::steady_clock::now();
    for (; !isDone.load(std::memory_order_relaxed); ) {
      // OPTIMIZATION:
      // Assuming checking the atomic bool costs a few iterations,
      // let do them all first and then check the bool once.
      // The value 128 here is just a guess.
      //
      for (unsigned hadmadeLoop__ = 0; hadmadeLoop__ < 128; ++hadmadeLoop__) {
        // Obtain the SHA256 hash of a random passphrase.
        PROFILE(auto const shaAt = std::chrono::steady_clock::now());
        picosha2::hash256_one_by_one hasher;
        // To avoid building a phrase by joining strings with a whitespace character
        // and to prevent unnecessary memory allocations we run the first separately
        // and run the loop for the rest:
        //  * feed the hasher with the first random word...
        for (unsigned i = 0; i < 1; ++i) {
          auto const wordIndex = dis(gen);
          decltype(auto) word = Words[wordIndex];
          wordIndices[i] = wordIndex;

          hasher.process(word.cbegin(), word.cend());
        }
        //  * feed with the rest random words with the leading whitespace character.
        for (unsigned i = 1; i < nWords_; ++i) {
          auto const wordIndex = dis(gen);
          decltype(auto) word = Words[wordIndex];
          wordIndices[i] = wordIndex;

          hasher.process(Whitespace.cbegin(), Whitespace.cend());
          hasher.process(word.cbegin(), word.cend());
        }
        hasher.finish();
        hasher.get_hash_bytes(secretKey.begin(), secretKey.end());
        PROFILE(shaTime += std::chrono::steady_clock::now() - shaAt);

        // We've got the key in `secretKey`, which is used in X25519 hashing algorithm
        // as the private key.
        // The next we do is obtaining the public key.

        PROFILE(auto const curveAt = std::chrono::steady_clock::now());
        X25519_KeyGen_x64(publicKey.data(), secretKey.data());
        PROFILE(curveTime += std::chrono::steady_clock::now() - curveAt);

        // Let's call it a nice try.
        ++stats_.tries;

        // As promised, `publicKey` contains the public key now, and
        // it is time to check if we have found the collision!
        // If so, mark our mission done and run away from the loops.
        if (publicKey == publicKeyReference) {
          hit = true;
          break;
        }
      }

      if (hit) {
        isDone.store(true, std::memory_order_relaxed);
        break;
      }
    }

    {
      stats_.elapsedTime = std::chrono::steady_clock::now() - startedAt;

      auto const speed = static_cast<double>(stats_.tries) / stats_.elapsedTime.count();
      std::vector<std::string> passphraseWords;
      std::transform(&wordIndices[0], &wordIndices[0] + nWords_,
                     std::back_inserter(passphraseWords),
                     [](auto i) -> std::string {
                       return gsl::to_string(Words[i]);
                     });
      std::string const passphrase = join(passphraseWords, ' ');

      // Lock the mutex to prevent threads from messing stdout.
      std::lock_guard<std::mutex> printingLock(printingMutex);
      std::cout << (hit ? (SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE)
                        : (SMITE SMITE SMITE SMITE SMITE SMITE SMITE SMITE SMITE SMITE)) << '\n'
                << "took " << stats_.elapsedTime.count() << " s"
                PROFILE(<< "\tsha256-ing  "     << shaTime.count() << " s")
                PROFILE(<< "\tcurve25519-ing  " << curveTime.count() << " s") << '\n'
                << "speed: " << speed << " tries/s per thread\n"
                << "tries: " << stats_.tries << '\n'
                << "passphrase: " << passphrase << '\n'
                << "secret key (sha256):  " << to_hexstring(secretKey) << '\n'
                << "public key:           " << to_hexstring(publicKey) << '\n'
                << "reference public key: " << to_hexstring(publicKeyReference) << '\n';
    }
  }

 private:
  unsigned nWords_;
  Stats    stats_;
};

int main(int argc, char *argv[]) {
  if (argc < 2) {
    Usage(argv[0]);
    return 1;
  }

  int const numOfWords = std::atoi(argv[1]);
  if (numOfWords < 1 || static_cast<unsigned>(numOfWords) > nWallets) {
    Usage(argv[0]);
    return 2;
  }

  unsigned const nThreads = std::max(1u, std::thread::hardware_concurrency());
  std::cout << "Starting on " << Wallets[numOfWords - 1] << '\n'
            << "Dict size: " << DictSize << "; " << numOfWords << "-word passphrase\n"
            << "Concurrency: " << std::thread::hardware_concurrency() << " vCPUs; "
            << "running " << nThreads << " threads\n";

  std::mutex       printingMutex;
  std::atomic_bool isDone{false};

  std::forward_list<std::thread> threads;
  for (unsigned i = 0; i < nThreads; ++i) {
    threads.emplace_front(Hashing(numOfWords), std::ref(printingMutex), std::ref(isDone));
  }

  for (auto &thread : threads) {
    thread.join();
  }

  return 0;
}

void Usage(char const *progname) {
  std::cout << "Usage: " << progname << " <1..12>\n"
            << '\n'
            << "Acknowledges:\n"
            << " * SHA256:         https://github.com/okdshin/PicoSHA2\n"
            << " * curve25519:     https://github.com/armfazh/rfc7748_precomputed\n"
            << " * GSL:            https://github.com/Microsoft/GSL\n";
}
