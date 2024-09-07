#!/bin/sh

# https://github.com/amagovpt/autenticacao.gov/issues/31

set -eux

sudo apt install -y \
  libcjson-dev \
	libcurl4-nss-dev \
	libnsspem \
	libopenjp2-7-dev \
	libpcsclite-dev \
	libpng-dev \
	libpoppler-qt5-dev \
	libssl-dev \
	libxerces-c-dev \
	libxml-security-c-dev \
	libzip-dev \
	openjdk-11-jdk \
	pcscd \
	qml-module-qt-labs-folderlistmodel \
	qml-module-qt-labs-platform \
	qml-module-qt-labs-settings \
	qml-module-qtquick2 \
	qml-module-qtquick-controls \
	qml-module-qtquick-controls2 \
	qml-module-qtquick-dialogs \
	qml-module-qtquick-layouts \
	qml-module-qtquick-window2 \
	qt5-gtk-platformtheme \
	qt5-qmake \
	qtbase5-dev \
	qtbase5-private-dev \
	qtdeclarative5-dev \
	qtquickcontrols2-5-dev \
	swig
if [ ! -d ~/opt/autenticacao.gov ]; then
  git clone https://github.com/amagovpt/autenticacao.gov ~/opt/autenticacao.gov
fi
export OPENSSL_NO_DEPRECATED_3_0=1
cd ~/opt/autenticacao.gov/pteid-mw-pt/_src/eidmw \
  && qmake pteid-mw.pro \
  && env make OPENSSL_NO_DEPRECATED_3_0=1 \
  && sudo make install \
  && sudo ldconfig

# eidguiV2
