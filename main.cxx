#include <algorithm>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <forward_list>
#include <random>
#include <thread>

#include "main.hxx"

#include <gsl/gsl>
#include <picosha2.h>
#include <pthread.h>
#include <rfc7748_precompted.h>

// This graphics dramatically slows down my terminal, man. So it is disabled
// for non-release builds.
#ifdef NDEBUG
# define SMILE "🌝"
#else
# define SMILE "-"
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

template <typename Iterable>
std::string to_hexstring(Iterable a) {
  return to_hexstring(std::cbegin(a), std::cend(a));
}

struct Hashing {
  Hashing(unsigned nWords)
      : nWords_(nWords)
  {}
  Hashing(Hashing const &other) = delete;
  Hashing(Hashing&& other)
      : nWords_(other.nWords_)
      , tries_(other.tries_)
  {}
  ~Hashing() {
    std::cout << "~Hashing()" << std::endl;
  }

  void operator () (std::mutex &doneMutex, std::condition_variable &doneCondVar) {    
    std::random_device rd;  // will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> dis(0, DictSize - 1);
    std::array<unsigned char, 32> secretKey;
    std::array<unsigned char, 32> publicKey;
    std::array<unsigned char, 32> basepoint;
    int wordIndices[nWords_];
    for (auto &c : basepoint) {
      c = 0;
    }
    basepoint[0] = 9;

    auto const startedAt = std::chrono::steady_clock::now();

    while (true) {
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

      // X25519_Shared_x64(publicKey.data(), basepoint.data(), secretKey.data());
      X25519_KeyGen_x64(publicKey.data(), secretKey.data());

      ++tries_;

      if (publicKey == PublicKeys[nWords_ - 1]) {
        {
          std::lock_guard<std::mutex> doneLock(doneMutex);
          auto const elapsedTime = std::chrono::steady_clock::now() - startedAt;

          std::cout << SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE SMILE << '\n';
          std::cout << "took " << std::chrono::duration<double>(elapsedTime).count() << " s\n";
          std::cout << "speed " << static_cast<double>(tries_) / std::chrono::duration<double>(elapsedTime).count() << " try/s\n";
          std::cout << "tries: "<< tries_ << '\n';
          std::cout << "passphrase: ";
          for (auto const i : wordIndices) {
            std::cout << gsl::to_string(Words[i]) << ' ';
          }
          std::cout << '\n';
          std::cout << "basepoint:            " << to_hexstring(basepoint) << '\n';
          std::cout << "secret key:           " << to_hexstring(secretKey) << '\n';
          std::cout << "public key:           " << to_hexstring(publicKey) << '\n';
          std::cout << "reference public key: " << to_hexstring(PublicKeys[nWords_ - 1]) << '\n';
        }

        doneCondVar.notify_one();

        break;
      }

      // if (tries > 10)
      //   break;
    }
  }

 private:
  unsigned nWords_;
  std::size_t tries_ = 0;
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

  unsigned const nThreads = std::max(1u, std::thread::hardware_concurrency());
  std::cout << "Starting on " << Wallets[numOfWords - 1] << '\n';
  std::cout << "Dict size: " << DictSize << '\n';
  std::cout << numOfWords << "-word passphrase\n";
  std::cout << "# of CPUs: " << std::thread::hardware_concurrency() << '\n';
  std::cout << "# of running threads: " << std::thread::hardware_concurrency() << '\n';

  std::mutex doneMutex;
  std::condition_variable doneCondVar;

  std::forward_list<std::thread> threads;
  std::forward_list<std::thread::native_handle_type> nativeThreads;
  for (unsigned i = 0; i < nThreads; ++i) {
    std::thread thread(Hashing(numOfWords), std::ref(doneMutex), std::ref(doneCondVar));
    nativeThreads.push_front(thread.native_handle());
    thread.detach();
    threads.push_front(std::move(thread));
  }

  {
    std::unique_lock<std::mutex> doneLock(doneMutex);
    doneCondVar.wait(doneLock);
  }
  for (auto &thread : threads) {
    // break;

    // lk.unlock();
    // doneCondVar.notify_one()

    if (thread.joinable()) {
      thread.std::thread::~thread();
      // thread.join();
      // thread.detach();
      ::pthread_cancel(thread.native_handle());
    }
  }

  return 0;
}

void Usage(char const *progname) {
  std::cout << "Usage: " << progname << " <1..12>\n\n"
            << "Acknowledges:\n"
            << " * SHA256 library: https://github.com/okdshin/PicoSHA2\n"
            << " * GSL:            https://github.com/Microsoft/GSL\n";
}
