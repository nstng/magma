#!/usr/bin/env bash
set -euo pipefail

function join_by {
  local d=" -o " f=${1-}
  if shift 1; then
    printf %s " -path $f" "${@/#/$d-path }"
  fi
}

DENY_LIST=(
	"./orc8r/gateway/python/build"
	"./lte/gateway/python/build"
	"./ci-scripts"
	"./example"
	"./orc8r/tools/fab"
	"./orc8r/cloud/deploy/orc8r_deployer"
	"./lte/gateway/python/magma/pipelined"
	"./lte/gateway/python/integ_tests"
)

DENY=$(join_by "${DENY_LIST[@]}")

ALL_PY_FILES=$(find . \( $DENY \) -prune -o -iname "*.py" -print)


for file in $ALL_PY_FILES
do
	PY_PATH=$(dirname "$file")
	PY_FILE=$(basename "$file")

	if [ $PY_FILE = "__init__.py" ] || [ $PY_FILE = "setup.py" ]  || [ $PY_FILE = "fabfile.py" ];
	then
		continue
	fi

	BUILD_FILE="${PY_PATH}/BUILD.bazel"
	if test -f "$BUILD_FILE"; then
		if ! grep -q "$PY_FILE" "$BUILD_FILE";
		then
			echo "$file"
		fi
	else
    	echo "$file"
	fi
done


