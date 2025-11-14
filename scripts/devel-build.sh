#!/bin/bash

set -euxo pipefail
cd "${0%/*}"
cd ..

# Sanity checks
if [ ! -e "CMakeLists.txt" ] || [ ! -e "src/odhcpd.c" ]; then
	echo "odhcpd checkout not found" >&2
	exit 1
fi

if [ $# -eq 0 ]; then
	BUILD_ARGS="-DDHCPV4_SUPPORT=ON"
else
	BUILD_ARGS="$@"
fi

# Create build dirs
ODHCPDDIR="$(pwd)"
BUILDDIR="${ODHCPDDIR}/build"
DEPSDIR="${BUILDDIR}/depends"
[ -e "${BUILDDIR}" ] || mkdir "${BUILDDIR}"
[ -e "${DEPSDIR}" ] || mkdir "${DEPSDIR}"

# Download deps
cd "${DEPSDIR}"
[ -e "json-c" ] || git clone https://github.com/json-c/json-c.git
[ -e "libnl-tiny" ] || git clone https://github.com/openwrt/libnl-tiny.git
[ -e "libubox" ] || git clone https://github.com/openwrt/libubox.git
[ -e "uci" ] || git clone https://github.com/openwrt/uci.git
[ -e "ubus" ] || git clone https://github.com/openwrt/ubus.git

# Build json-c
cd "${DEPSDIR}/json-c"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DBUILD_SHARED_LIBS=OFF				\
	-DDISABLE_EXTRA_LIBS=ON				\
	-DBUILD_TESTING=OFF				\
	--install-prefix "${BUILDDIR}"
make
make install

# Build libnl-tiny
cd "${DEPSDIR}/libnl-tiny"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	--install-prefix "${BUILDDIR}"
make
make install

# Build libubox
cd "${DEPSDIR}/libubox"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DBUILD_LUA=OFF					\
	-DBUILD_EXAMPLES=OFF				\
	--install-prefix "${BUILDDIR}"
make
make install

# Build ubus
cd "${DEPSDIR}/ubus"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DBUILD_LUA=OFF					\
	-DBUILD_EXAMPLES=OFF				\
	--install-prefix "${BUILDDIR}"
make
make install

# Build uci
cd "${DEPSDIR}/uci"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DBUILD_LUA=OFF					\
	--install-prefix "${BUILDDIR}"
make
make install

# Build odhcpd
cd "${ODHCPDDIR}"
cmake							\
	-S .						\
	-B "${BUILDDIR}"				\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	${BUILD_ARGS}
make -C "${BUILDDIR}"

set +x
echo "✅ Success - the odhcpd binary is available at ${BUILDDIR}/odhcpd"
echo "👷 You can rebuild odhcpd by running 'make -C build'"

exit 0
