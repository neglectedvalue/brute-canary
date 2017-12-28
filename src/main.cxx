#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <iomanip>
#include <iostream>
#include <forward_list>
#include <random>
#include <thread>
#include <mutex>

#include "main.hxx"

#include <gsl/gsl>
#include <picosha2.h>
#include <pthread.h>
#include <rfc7748_precompted.h>

// This graphics dramatically slows down my terminal, man. So it is disabled
// for non-release builds.
#if defined(NDEBUG)
# define SMILE " 🌝 "
#else
# define SMILE "-"
#endif

#if defined(NDEBUG)
# define SMITE " 🌚 "
#else
# define SMITE "-"
#endif

#if defined(PROFILE)
# undef PROFILE
# define PROFILE(...) __VA_ARGS__
#else
# define PROFILE(...)
#endif

template <typename Iterator>
std::string to_hexstring(Iterator b, Iterator e) {
  std::stringstream ss;

  ss << std::hex;
  for (decltype(auto) iter = b; iter != e; ++iter) {
    ss << std::setw(2) << std::setfill('0') << int{*iter};
  }

  return ss.str();
}

template <typename Iterator>
std::string join(Iterator b, Iterator e, char const sep) {
  std::stringstream ss;

  decltype(auto) iter = b;
  if (iter != e) {
    ss << *iter;
  }
  for (++iter; iter != e; ++iter) {
    ss << sep << *iter;
  }

  return ss.str();
}

template <typename Iterable>
std::string to_hexstring(Iterable a) {
  return to_hexstring(std::cbegin(a), std::cend(a));
}

template <typename Iterable>
std::string join(Iterable a, char const sep) {
  return join(std::cbegin(a), std::cend(a), sep);
}

struct Hashing {
  Hashing(unsigned nWords)
      : nWords_(nWords)
  {}
  Hashing(Hashing const &other) = delete;
  Hashing(Hashing&& other)
      : nWords_(other.nWords_), tries_(other.tries_)
  {}

  void operator () (std::mutex &doneMutex, std::condition_variable &doneCondVar,
                    std::atomic_bool &finished) {
    PROFILE(
        std::chrono::steady_clock::duration shaTime{0};
        std::chrono::steady_clock::duration curveTime{0};
    )

    running_ = true;

    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<> dis(0, DictSize - 1);
    std::array<unsigned char, 32> secretKey;
    std::array<unsigned char, 32> publicKey;
    auto const &publicKeyReference = PublicKeys[nWords_ - 1];
    int wordIndices[nWords_];
    bool hit = false;

    auto const startedAt = std::chrono::steady_clock::now();

    for (tries_ = 0; !finished.load(std::memory_order_relaxed); ) {
      // Assuming checking the atomic bool costs a few iterations,
      // let do them all first and then check the bool once.
      // The value 128 here is just a guess.
      for (unsigned hadmadeLoop = 0; hadmadeLoop < 128; ++hadmadeLoop, ++tries_) {
        PROFILE(auto const shaAt = std::chrono::steady_clock::now());
        picosha2::hash256_one_by_one hasher;

        for (unsigned i = 0; i < 1; ++i) {
          auto const wordIndex = dis(gen);
          decltype(auto) word = Words[wordIndex];
          wordIndices[i] = wordIndex;

          hasher.process(word.cbegin(), word.cend());
        }
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

        PROFILE(auto const curveAt = std::chrono::steady_clock::now());
        X25519_KeyGen_x64(publicKey.data(), secretKey.data());
        PROFILE(curveTime += std::chrono::steady_clock::now() - curveAt);

        if (publicKey == publicKeyReference) {
          hit = true;
          break;
        }
      }

      if (hit) {
        finished.store(true, std::memory_order_relaxed);
      }
    }

    {
      std::lock_guard<std::mutex> doneLock(doneMutex);
      auto const elapsedTime = std::chrono::steady_clock::now() - startedAt;
      std::vector<std::string> passphraseWords;
      std::transform(&wordIndices[0], &wordIndices[0] + nWords_,
                     std::back_inserter(passphraseWords),
                     [](auto i) -> std::string {
                       return gsl::to_string(Words[i]);
                     });

      std::cout << (hit
                    ? (SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE)
                    : (SMITE SMITE SMITE SMITE SMITE SMITE SMITE SMITE SMITE SMITE))
                << '\n'
                << "took " << std::chrono::duration<double>(elapsedTime).count() << " s"
                PROFILE(<< "\tsha256-ing  "     << std::chrono::duration<double>(shaTime).count() << " s")
                PROFILE(<< "\tcurve25519-ing  " << std::chrono::duration<double>(curveTime).count() << " s") << '\n'
                << "speed " << static_cast<double>(tries_) / std::chrono::duration<double>(elapsedTime).count() << " guess/s per thread\n"
                << "tries: "<< tries_ << '\n'
                << "passphrase: " << join(std::begin(passphraseWords), std::end(passphraseWords), ' ') << '\n'
                << "secret key:           " << to_hexstring(secretKey) << '\n'
                << "public key:           " << to_hexstring(publicKey) << '\n'
                << "reference public key: " << to_hexstring(publicKeyReference) << '\n';
    }
    doneCondVar.notify_one();
  }

 private:
  unsigned    nWords_;
  std::size_t tries_ = 0;

  volatile bool running_ = false;
};

int main(int argc, char *argv[]) {
  if (argc < 2) {
    Usage(argv[0]);
    return 1;
  }

  int const numOfWords = std::atoi(argv[1]);
  if (numOfWords < 1 || static_cast<unsigned>(numOfWords) > sizeof Wallets / sizeof Wallets[0]) {
    Usage(argv[0]);
    return 2;
  }

  unsigned const nThreads = std::max(1u, std::thread::hardware_concurrency() * 2);
  std::cout << "Starting on " << Wallets[numOfWords - 1] << '\n';
  std::cout << "Dict size: " << DictSize << "; " << numOfWords << "-word passphrase\n";
  std::cout << "Concurrency: " << std::thread::hardware_concurrency() << " vCPUs using "
            << nThreads << " threads\n";

  std::mutex doneMutex;
  std::condition_variable doneCondVar;
  std::atomic_bool finished;

  std::forward_list<std::thread> threads;
  for (unsigned i = 0; i < nThreads; ++i) {
    threads.emplace_front(Hashing(numOfWords), std::ref(doneMutex), std::ref(doneCondVar),
                          std::ref(finished));

    // Hashing hasher((numOfWords), std::ref(doneMutex), std::ref(doneCondVar));
    // nativeThreads.push_front(thread.native_handle());
    // std::thread thread(Hashing(numOfWords), std::ref(doneMutex), std::ref(doneCondVar));
    // nativeThreads.push_front(thread.native_handle());
    // thread.detach();
    // threads.push_front(std::move(thread));
  }

  {
    std::unique_lock<std::mutex> doneLock(doneMutex);
    doneCondVar.wait(doneLock);
    finished = true;
  }
  for (auto &thread : threads) {

    if (thread.joinable()) {
      thread.join();
    }
  }

  return 0;
}

void Usage(char const *progname) {
  std::cout << "Usage: " << progname << " <1..12>\n\n"
            << "Acknowledges:\n"
            << " * SHA256:         https://github.com/okdshin/PicoSHA2\n"
            << " * curve25519:     https://github.com/armfazh/rfc7748_precomputed\n"
            << " * GSL:            https://github.com/Microsoft/GSL\n";
}
