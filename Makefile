# GCC_DIR=/usr/local/Cellar/gcc/7.2.0
# AR=$(GCC_DIR)/bin/gcc-ar-7
# AR=/usr/bin/ar
# CC=$(GCC_DIR)/bin/gcc-7
# GCC=$(GCC_DIR)/bin/g++-7
# CPP=$(GCC_DIR)/bin/cpp-7
# AS=$(CC)

GCC_DIR=/usr
CC=$(GCC_DIR)/bin/gcc
CXX=$(GCC_DIR)/bin/g++
GCC=$(GCC_DIR)/bin/gcc
CPP=$(GCC_DIR)/bin/cpp
AS=$(GCC_DIR)/bin/as
AR=$(GCC_DIR)/bin/ar

# CURVE_DIR=thirdparty/curve25519-85dcab1300ff1b196042839de9c8bbea26329537
CRYPTO_DIR=thirdparty/rfc7748_precomputed-5155426d79f60092df3cce540fbadfcdfcd56245
GSL_DIR=thirdparty/GSL-9d65e74400976b3509833f49b16d401600c7317d
SODIUM_DIR=thirdparty/libsodium-1.0.16
PICOSHA2_DIR=thirdparty/picosha2

CFLAGS=-Wall -Wextra -Wno-vla-extension -Ofast -pedantic -mbmi -mbmi2 -march=native -mtune=native

CPPFLAGS=					\
	-I$(GSL_DIR)/include			\
	-I$(CRYPTO_DIR)/include			\
	-I$(PICOSHA2_DIR)
#	-I$(CURVE_DIR)/C++			\
#	-I$(SODIUM_DIR)/r/include		\

LDFLAGS=					\
# 	-L$(SODIUM_DIR)/r/lib -lsodium

.PHONY: all clean # curve sodium

all: main

sodium:
	cd $(SODIUM_DIR) &&				\
	sh autogen.sh &&				\
	mkdir -p b && cd b &&				\
	env AR=$(AR) CCAS=$(CC)				\
	    CC=$(CC) CPP=$(CPP)				\
	../configure --prefix=$$(pwd)/../r		\
	             --disable-debug			\
	             --disable-dependency-tracking	\
	             --enable-opt			\
	             --disable-ssp &&			\
	$(MAKE) install

curve:
	$(MAKE) RELEASE=1			\
	  MAKE_STATIC_COMMAND="$(CC) -o"	\
	  AR=$(AR) AS=$(AS)			\
	  CC=$(CC) GPP=$(CXX) CPP=$(CPP)	\
	  -C $(CURVE_DIR) clean test asm

CRYPTO_HDRS = $(wildcard $(CRYPTO_DIR)/src/*.h)
CRYPTO_SRCS = $(wildcard $(CRYPTO_DIR)/src/*.c)
CRYPTO_OBJS = $(CRYPTO_SRCS:%.c=%.o)

$(CRYPTO_DIR)/src/%.o: $(CRYPTO_DIR)/src/%.c $(CRYPTO_HDRS)
	$(CC) -std=c11 $(CFLAGS) -I$(CRYPTO_DIR)/include -o $@ -c $<

crypto.a: $(CRYPTO_OBJS)
	$(AR) cru $@ $^

HDRS = $(wildcard *.hxx)
SRCS = $(wildcard *.cxx)
OBJS = $(SRCS:%.cxx=%.o)

%.o: %.cxx $(HDRS)
	$(CXX) -std=c++1z $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

main: $(OBJS) crypto.a
	$(CXX) $(LDFALGS) $^ -o main

clean: $(CRYPTO_OBJS) crypto.a main
	-rm -f $?
