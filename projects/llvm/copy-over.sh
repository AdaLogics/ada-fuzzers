# This assumes ada-fuzzers is located under $SRC/ada-fuzzers and will copy
# over all fuzzers into mainstream llvm at $SRC/llvm-project

ADA_SRC=$SRC/ada-fuzzers/project/llvm/
LLVM_DST=$SRC/llvm-project

cp -rf $ADA_SRC/llvm-parse-assembly-fuzzer $LLVM_DST/llvm/tools/llvm-parse-assembly-fuzzer
