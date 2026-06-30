# Build numpy with address sanitizer and undefined behavior sanitizer instrumentation
CC="$CONDA_PREFIX/bin/clang" \
CXX="$CONDA_PREFIX/bin/clang++" \
CFLAGS="-fsanitize=address,fuzzer-no-link -g -O1" \
CXXFLAGS="-fsanitize=address,fuzzer-no-link -g -O1" \
LDFLAGS="-fsanitize=address,fuzzer-no-link" \
pip install numpy --no-binary numpy --force-reinstall --no-cache-dir

# Check instrumentation
NPCORE=$(find "$CONDA_PREFIX" -path "*/numpy/_core/_multiarray_umath*.so" 2>/dev/null | head -1)
echo "$NPCORE"
nm -D "$NPCORE" | grep -i asan | head
nm -D "$NPCORE" | grep -i sancov | head

# Preloading plain libclang-rt.asan.so (Not ideal)
LD_PRELOAD=$(clang -print-file-name=libclang_rt.asan-x86_64.so) \
python -c "import numpy; print(numpy.__version__)"

# Preload with atheris ASAN
LD_PRELOAD="$(python -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so" \
ASAN_OPTIONS=detect_leaks=0,detect_odr_violation=0,allocator_may_return_null=1 \
python numpy_fuzz.py corpus/