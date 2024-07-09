# Building PowerDNS with support for PQC algorithms

This document describes how to build our patched PowerDNS and the libraries that it depends on.
After following these steps, you'll have a PowerDNS Recursor and PowerDNS Authoritative that support Falcon (the 512-bit variant), MAYO (parameter set 2), and SQISign (parameter set NIST-I).
Instead of following these steps, you can also use Docker containers and other tools provided by us to bring up a PQC DNSSEC testbed.
Read more about this work [here](https://patad.sidnlabs.nl/).

## 1. Clone repositories

Create a directory to store all git repositories, clone the git repositories and check out the proper versions.
Note that we clone PowerDNS from our own repository and use our own branch, since we patched it.

```
$ mkdir workspace
$ cd workspace/
$ git clone https://github.com/SIDN/pdns
$ cd pdns && git checkout master-pqc-20240606-1 && cd -
$ git clone https://github.com/PQClean/PQClean
$ cd PQClean && git checkout 0cdedc78dc429ef3dd251257d9f2634e725d0536 && cd -
$ git clone https://github.com/SQISign/the-sqisign
$ cd the-sqisign && git checkout df24e34993206d5a53061ba667a580f9b65dc8a1 && cd -
$ git clone https://github.com/PQCMayo/MAYO-C
$ cd MAYO-C && git checkout fc9079fb5ac5cd4af98e3e0f094a0a3cf2a01499 && cd -
```

## 2. Compile Falcon

```
$ cd workspace/PQClean/crypto_sign/falcon-512/clean
$ make
$ ln -s ../../../common/randombytes.c
$ EXTRAFLAGS="-Wno-sign-conversion -Wno-conversion" make randombytes.o
$ ar -r libfalcon-512_clean.a randombytes.o
```

Now, only execute the following block of commands *if you are compiling PowerDNS with just Falcon-512*. If you are also compiling in SQISign, you must to skip the following block of commands.

```
$ ln -s ../../../common/fips202.c
$ make fips202.o
$ ar -r libfalcon-512_clean.a fips202.o
```

In both cases, continue here.
```
$ sudo mkdir -p /usr/lib/patad-testbed
$ sudo cp libfalcon-512_clean.a /usr/lib/patad-testbed
$ sudo cp api.h /usr/include/patad-testbed/falcon512.h
$ for f in /usr/lib/patad-testbed/libfalcon*.a ; do sudo ln -s $f /usr/lib ; done
```

## 3. Compile SQISign

```
$ sudo apt install cmake libgmp-dev
$ cd workspace/the-sqisign
$ sudo mkdir -p /usr/include/patad-testbed
$ echo '#ifndef sqisign1_h' | sudo tee /usr/include/patad-testbed/sqisign1.h
$ echo '#define sqisign1_h' | sudo tee -a /usr/include/patad-testbed/sqisign1.h
$ echo | sudo tee -a /usr/include/patad-testbed/sqisign1.h
$ grep CRYPTO src/nistapi/lvl1/api.h | sudo tee -a /usr/include/patad-testbed/sqisign1.h
$ sudo sed -i -e 's/CRYPTO/SQISIGN1/g' /usr/include/patad-testbed/sqisign1.h
$ echo | sudo tee -a /usr/include/patad-testbed/sqisign1.h
$ grep -E -v 'SQISIGN_H|endif' include/sig.h | sudo tee -a /usr/include/patad-testbed/sqisign1.h
$ echo '#endif /* sqisign1_h */' | sudo tee -a /usr/include/patad-testbed/sqisign1.h
$ mkdir -p build
$ cd build
$ cmake -DSQISIGN_BUILD_TYPE=ref ..
$ make sqisign_lvl1
$ sudo mkdir -p /usr/lib/patad-testbed
$ sudo cp src/libsqisign_lvl1.a \
    src/klpt/ref/lvl1/libsqisign_klpt_lvl1.a \
    src/intbig/ref/generic/libsqisign_intbig_generic.a \
    src/id2iso/ref/lvl1/libsqisign_id2iso_lvl1.a \
    src/quaternion/ref/generic/libsqisign_quaternion_generic.a \
    src/gf/ref/lvl1/libsqisign_gf_lvl1.a \
    src/protocols/ref/lvl1/libsqisign_protocols_lvl1.a \
    src/ec/ref/lvl1/libsqisign_ec_lvl1.a \
    src/precomp/ref/lvl1/libsqisign_precomp_lvl1.a \
    src/common/generic/libsqisign_common_sys.a \
    /usr/lib/patad-testbed/
$ for f in /usr/lib/patad-testbed/libsqisign*.a ; do sudo ln -s $f /usr/lib ; done
```

## 4. Compile MAYO

```
$ cd workspace/MAYO-C
$ sudo mkdir -p /usr/include/patad-testbed
$ sudo cp include/mayo.h /usr/include/patad-testbed
$ mkdir -p build
$ cd build
```

Now, decide if you want to build an AVX2-enabled (faster) version of MAYO, or whether you want MAYO to be able to run on all CPUs.
If you want to use AVX2, run:
```
$ cmake -DMAYO_BUILD_TYPE=avx2 ..
$ echo "#define MAYO_BUILD_TYPE_AVX2" | sudo tee /usr/include/patad-testbed/mayo-build-type.h
```
Else, run:
```
$ cmake -DMAYO_BUILD_TYPE=opt ..
$ echo "#define MAYO_BUILD_TYPE_OPT" | sudo tee /usr/include/patad-testbed/mayo-build-type.h
```

And continue here:
```
$ make
$ ar d src/libmayo_common_sys.a aes_c.c.o fips202.c.o randombytes_system.c.o
$ sudo mkdir -p /usr/lib/patad-testbed
$ sudo cp src/libmayo_2.a src/libmayo_common_sys.a /usr/lib/patad-testbed
$ for f in /usr/lib/patad-testbed/libmayo*.a ; do sudo ln -s $f /usr/lib ; done
```

## 5. Compile our patched PowerDNS Authoritative

```
$ cd workspace/pdns
$ sudo apt install g++ libboost-all-dev libtool make pkg-config default-libmysqlclient-dev libssl-dev libluajit-5.1-dev python3-venv
$ sudo apt install autoconf automake ragel bison flex
$ sudo apt install libcurl4-openssl-dev luajit lua-yaml-dev libyaml-cpp-dev libtolua-dev lua5.3 libboost-all-dev libtool lua-yaml-dev libyaml-cpp-dev libcurl4 gawk libsqlite3-dev
$ autoreconf -vi
$ ./configure --with-modules="bind" --with-sqlite3 --with-falcon --with-mayo --with-sqisign --disable-lua-records
$ make
```

## 6. Compile our patched PowerDNS Recursor

```
$ cd workspace/pdns/recursordist
$ sudo apt install g++ libboost-all-dev libtool make pkg-config default-libmysqlclient-dev libssl-dev libluajit-5.1-dev python3-venv
$ sudo apt install autoconf automake ragel bison flex
$ sudo apt install libcurl4-openssl-dev luajit lua-yaml-dev libyaml-cpp-dev libtolua-dev lua5.3 libboost-all-dev libtool lua-yaml-dev libyaml-cpp-dev libcurl4 gawk libsqlite3-dev cargo
$ autoreconf -vi
$ ./configure --with-falcon --with-mayo --with-sqisign
$ make
```

