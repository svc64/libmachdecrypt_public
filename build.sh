#!/bin/bash
xcodebuild -configuration Release -toolchain com.naville.hikari
strip -r -S -x ./build/Release/liblibmachdecrypt.dylib
