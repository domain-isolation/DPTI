#!/bin/bash
make -C linux-sgx-driver all
make -C linux-sgx deb_psw_pkg_minimal
# please follow the installation guide of the psw!