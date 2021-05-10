#!/bin/bash
git clone https://github.com/intel/linux-sgx.git
git clone https://github.com/intel/linux-sgx-driver.git

# patch psw
cd linux-sgx
git checkout 60d36e0de7055e8edd2fe68693b3c39f3f10fd3c
git apply ../dpti-psw.patch
cd ..

# patch sdk
cd linux-sgx-driver
git checkout 3a4f6ac598f89a3ba3c423335841fe250495f4b9
git apply ../dpti-driver.patch
cd ..