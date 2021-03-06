ifeq ($(filter 1 y yes, $(GCC7)),)
  GCC_DIR = /usr
  CC  = $(GCC_DIR)/bin/gcc
  CXX = $(GCC_DIR)/bin/g++
  GCC = $(GCC_DIR)/bin/gcc
  CPP = $(GCC_DIR)/bin/cpp
  AS  = $(GCC_DIR)/bin/as
  AR  = $(GCC_DIR)/bin/ar
else
  # Toolchain for gcc-7 on OS X.
  GCC_DIR = /usr/local/Cellar/gcc/7.2.0
  CC  = $(GCC_DIR)/bin/gcc-7
  CXX = $(GCC_DIR)/bin/g++-7
  GCC = $(GCC_DIR)/bin/gcc-7
  CPP = $(GCC_DIR)/bin/cpp-7
  AS  = /usr/bin/as
  AR  = /usr/bin/ar
endif

GSL_DIR      = thirdparty/GSL-9d65e74400976b3509833f49b16d401600c7317d
PICOSHA2_DIR = thirdparty/picosha2
CRYPTO_DIR   = thirdparty/rfc7748_precomputed-5155426d79f60092df3cce540fbadfcdfcd56245

CRYPTO_HDRS = $(wildcard $(CRYPTO_DIR)/src/*.h)
CRYPTO_SRCS = $(wildcard $(CRYPTO_DIR)/src/*.c)
CRYPTO_OBJS = $(CRYPTO_SRCS:%.c=%.o)

HDRS = $(wildcard src/*.hxx)
SRCS = $(wildcard src/*.cxx)
OBJS = $(SRCS:%.cxx=%.o)

CFLAGS=								\
	-pedantic -Wall -Wextra -Wno-vla-extension -Wno-vla	\
	-march=native -Ofast -mbmi -mbmi2			\
	-funroll-loops

CPPFLAGS=						\
	$(if $(filter 1 y yes, $(RELEASE)),-DNDEBUG,)	\
	-I$(GSL_DIR)/include				\
	-I$(PICOSHA2_DIR)				\
	-I$(CRYPTO_DIR)/include

# Not working on OS X.
# CURVE_DIR=thirdparty/curve25519-85dcab1300ff1b196042839de9c8bbea26329537
#
# Include path: -I$(CURVE_DIR)/C++
#
# curve:
# 	$(MAKE) RELEASE=1			\
# 	  MAKE_STATIC_COMMAND="$(CC) -o"	\
# 	  AR=$(AR) AS=$(AS)			\
# 	  CC=$(CC) GPP=$(CXX) CPP=$(CPP)	\
# 	  -C $(CURVE_DIR) clean test asm

.PHONY: all clean distclean

all: src/main

clean:
	-rm -f $(OBJS) src/main

distclean: clean
	-rm -f $(CRYPTO_OBJS) src/crypto.a

$(CRYPTO_DIR)/src/%.o: $(CRYPTO_DIR)/src/%.c $(CRYPTO_HDRS)
	$(CC) -std=c11 $(CFLAGS) -I$(CRYPTO_DIR)/include -o $@ -c $<

src/crypto.a: $(CRYPTO_OBJS)
	$(AR) cr $@ $^

src/%.o: src/%.cxx $(HDRS)
	$(CXX) -std=c++1z $(CFLAGS) $(CPPFLAGS)			\
	       -pthread						\
	       $(if $(filter 1 y yes, $(PROFILE)),-DPROFILE,)	\
	       -o $@ -c $<

src/main: $(OBJS) src/crypto.a
	$(CXX) -pthread -lpthread $(LDFALGS) $^ -o $@
