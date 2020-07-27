#!/bin/bash

pushd 3rd-party
  ./get-boost.sh clean
#  ./get-botan.sh clean # removed because Boost uses openssl for asio
  ./get-openssl.sh clean
  ./get-sqlite.sh clean
  ./get-rapidjson.sh clean
# testing framweworks
  ./get-catch2.sh clean
  rm .gitignore
popd

rm -rf common