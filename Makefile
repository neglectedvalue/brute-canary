ifeq ($(GCC7),1)
GCC_DIR=/usr/local/Cellar/gcc/7.2.0
# AR=$(GCC_DIR)/bin/gcc-ar-7
CC=$(GCC_DIR)/bin/gcc-7
CXX=$(GCC_DIR)/bin/g++-7
GCC=$(GCC_DIR)/bin/gcc-7
CPP=$(GCC_DIR)/bin/cpp-7
AS=/usr/bin/as
AR=/usr/bin/ar
else
GCC_DIR=/usr
CC=$(GCC_DIR)/bin/gcc
CXX=$(GCC_DIR)/bin/g++
GCC=$(GCC_DIR)/bin/gcc
CPP=$(GCC_DIR)/bin/cpp
AS=$(GCC_DIR)/bin/as
AR=$(GCC_DIR)/bin/ar
endif

# CURVE_DIR=thirdparty/curve25519-85dcab1300ff1b196042839de9c8bbea26329537
CRYPTO_DIR=thirdparty/rfc7748_precomputed-5155426d79f60092df3cce540fbadfcdfcd56245
GSL_DIR=thirdparty/GSL-9d65e74400976b3509833f49b16d401600c7317d
PICOSHA2_DIR=thirdparty/picosha2

CFLAGS=								\
	-pedantic -Wall -Wextra -Wno-vla-extension -Wno-vla	\
	-march=native -mtune=native -Ofast -mbmi -mbmi2

CPPFLAGS=						\
	$(if $(filter 1 y yes, $(RELEASE)),-DNDEBUG,)	\
	-I$(GSL_DIR)/include				\
	-I$(CRYPTO_DIR)/include				\
	-I$(PICOSHA2_DIR)
#	-I$(CURVE_DIR)/C++			\

LDFLAGS=					\

.PHONY: all clean # curve

all: main

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
	$(AR) cr $@ $^

HDRS = $(wildcard *.hxx)
SRCS = $(wildcard *.cxx)
OBJS = $(SRCS:%.cxx=%.o)

%.o: %.cxx $(HDRS)
	$(CXX) -std=c++1z $(CFLAGS) $(CPPFLAGS)			\
	       -pthread						\
	       $(if $(filter 1 y yes, $(PROFILE)),-DPROFILE,)	\
	       -o $@ -c $<

main: $(OBJS) crypto.a
	$(CXX) -pthread -lpthread $(LDFALGS) $^ -o main

clean:
	-rm -f $(CRYPTO_OBJS) crypto.a $(OBJS) main
