# Contributing to ObscuraProto

## Code Style

The project follows **Google** style with settings in `.clang-format`:

- **Indentation**: 4 spaces (no tabs)
- **Max line length**: 120 characters
- **Class names**: `CamelCase`
- **Variable and function names**: `snake_case`
- **Constant names**: `UPPER_SNAKE_CASE`
- **Const references**: west `const` (`const T&`, not `T const&`)
- **Namespaces**: indented contents (`NamespaceIndentation: All`)
- **Access sections (`public:`, `private:`)**: indented -4

Style is enforced automatically via `clang-format`. Do not deviate from what
the formatter produces — all `.cpp` and `.hpp` files are checked for style
compliance before each commit.

## Setting up pre-commit

1. **Install `pre-commit`** (choose one):
   ```bash
   brew install pre-commit           # macOS
   pip install pre-commit            # ubuntu
   ```

2. **Install `clang-format`** (if missing):
   ```bash
   brew install clang-format         # macOS
   # or from LLVM releases: https://releases.llvm.org/
   ```

3. **Install git hooks** (from repo root):
   ```bash
   pre-commit install
   ```

After this, `pre-commit` will automatically run `clang-format` on all `.cpp`
and `.hpp` files on every `git commit`. If the formatter changes anything, the
commit is rejected — re-add the modified files (`git add`) and retry
`git commit`.

## Formatting and linting

### Via pre-commit (automatic, on all files)

```bash
pre-commit run --all-files
```

### Manually, via clang-format

```bash
# Format a single file (modifies in place)
clang-format -i path/to/file.cpp

# Format all .cpp and .hpp files in the project
find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i

# Check only (no changes) — useful for CI
clang-format --dry-run --Werror path/to/file.cpp
```

### Build and tests

```bash
cmake -S . -B build
cmake --build build
cd build && ctest
```

Before submitting a pull request, make sure:
1. `pre-commit run --all-files` passes without errors.
2. The project builds without warnings.
3. All tests pass (`ctest`).
