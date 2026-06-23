# Contributing to ObscuraProto

## Code Style

Проект следует стилю **Google** с настройками в `.clang-format`:

- **Отступы**: 4 пробела (табуляция запрещена)
- **Максимальная длина строки**: 120 символов
- **Имена классов**: `CamelCase`
- **Имена переменных и функций**: `snake_case`
- **Имена констант**: `UPPER_SNAKE_CASE`
- **Константные ссылки**: west `const` (`const T&`, не `T const&`)
- **Пространства имён**: с отступом содержимого (`NamespaceIndentation: All`)
- **Секции доступа (`public:`, `private:`)**: с отступом -4

Стиль автоматически применяется через `clang-format`. Не отклоняйтесь от того,
что выдаёт форматтер — все `.cpp` и `.hpp` файлы проверяются на соответствие
стилю перед коммитом.

## Установка pre-commit

1. **Установите `pre-commit`** (одним из способов):
   ```bash
   brew install pre-commit           # macOS
   pip install pre-commit            # ubuntu
   ```

2. **Установите `clang-format`** (если его нет):
   ```bash
   brew install clang-format         # macOS
   # или из состава LLVM: https://releases.llvm.org/
   ```

3. **Установите git-хуки** (из корня репозитория):
   ```bash
   pre-commit install
   ```

После этого `pre-commit` будет автоматически запускать `clang-format` на всех
`.cpp` и `.hpp` файлах при каждом `git commit`. Если форматтер что-то меняет,
коммит отклонится — нужно заново добавить изменённые файлы (`git add`) и
повторить `git commit`.

## Форматирование и линтинг

### Через pre-commit (автоматически, на всех файлах)

```bash
pre-commit run --all-files
```

### Вручную, через clang-format

```bash
# Отформатировать один файл (изменяет файл на месте)
clang-format -i path/to/file.cpp

# Отформатировать все .cpp и .hpp файлы в проекте
find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i

# Только проверить (без изменений) — удобно для CI
clang-format --dry-run --Werror path/to/file.cpp
```

### Сборка и тесты

```bash
cmake -S . -B build
cmake --build build
cd build && ctest
```

Перед отправкой пул-реквеста убедитесь, что:
1. `pre-commit run --all-files` проходит без ошибок.
2. Проект собирается без предупреждений.
3. Все тесты проходят (`ctest`).
