#!/bin/bash
xcodebuild -configuration Release
strip -r -S -x ./build/Release/liblibmachdecrypt.dylib
