#!/bin/sh

# Check number of arguments
if [ "$#" -ne 1 ] ; then
    echo "Usage: $0 <project file>" >&2
    exit 1
fi

# Dependencies
apt update
apt upgrade -y
apt install -y --no-install-recommends python

# Install the ravenscar_full_nrf52832 BSP from bb-runtimes
git clone https://github.com/AdaCore/bb-runtimes.git
cd bb-runtimes
python ./build_rts.py --output=temp --bsps-only nrf52832
gprbuild -P temp/BSPs/ravenscar_full_nrf52832.gpr -j0 -f
gprinstall -P temp/BSPs/ravenscar_full_nrf52832.gpr -p -f
cd ..

# Build code
gprbuild -p -P $1 -j0 -f

# Prove code
gnatprove -P $1 --mode=all --level=3 -j0 --checks-as-errors