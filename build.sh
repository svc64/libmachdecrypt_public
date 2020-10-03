#!/bin/bash
xcodebuild -configuration Release
/usr/bin/strip -r -S -x ./build/Release/liblibmachdecrypt.dylib
