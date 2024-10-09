# libgroupsig

Welcome to _libgroupsig_, an extensible library for group signatures. Below,
you can find basic information about how to build the library. For more detailed
information on building it (the core and its wrappers), using it, contributing
and more, please check the [wiki](https://github.com/IBM/libgroupsig/wiki)
out.

## Build

Add the following variables to your environment:

```
export OPENSSL_ROOT_DIR=$(brew --prefix openssl) 
export OPENSSL_INCLUDE_DIR="${OPENSSL_ROOT_DIR}/include" 
export OPENSSL_LIBRARIES="${OPENSSL_ROOT_DIR}/lib"
```

The environment variables above are for MacOS. For Linux, replace ```$(brew --prefix openssl)``` in OPENSSL_ROOT_DIR with the path to the OpenSSL installation directory (e.g., ```/usr/local/ssl```).


To build the library, run the following commands.

```
mkdir build
cd build
cmake ..
make
```

## Install

To install the library, run the commands in build. Then, run:

```
make install
```

**Note**: You may require to run the previous command as super user.

## Tests and coverage

```
mkdir build
cd build
cmake -DUSE_GTEST=ON -DUSE_GCOV=ON ..
make && make test && make coverage
```

(Note: To build with debug flags, add the `-DCMAKE_BUILD_TYPE=Debug` modifier to
cmake in the prevous sequence of commands.)

Tests can alternatively be run with `ctest` from the build directory, or with
`ctest -T memcheck` to check memory-related bugs.

