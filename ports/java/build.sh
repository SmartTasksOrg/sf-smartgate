#!/usr/bin/env sh
# Build without Maven (JDK 17+): ./build.sh && java -cp build/classes cloud.smarttasks.smartgate.Conformance ../../spec/conformance
set -eu
cd "$(dirname "$0")"
rm -rf build/classes && mkdir -p build/classes
javac -Xlint:all,-serial -Werror --release 17 -d build/classes $(find src/main/java -name '*.java')
cp -r src/main/resources/. build/classes/
