CURVE_DIR=thirdparty/curve25519-85dcab1300ff1b196042839de9c8bbea26329537
GSL_DIR=thirdparty/GSL-9d65e74400976b3509833f49b16d401600c7317d

CPPFLAGS= \
	-I$(CURVE_DIR)/C++ \
	-I$(GSL_DIR)/include

.PHONY: all clean curve25519

curve25519:
	$(MAKE) RELEASE=1 -C $(CURVE_DIR) clean test asm

all: curve25519
	g++-7 -std=c++1z -fconcepts -O2 $(CPPFLAGS) main.cxx -o main
