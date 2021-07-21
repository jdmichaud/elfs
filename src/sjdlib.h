#ifndef RESULT_SJDLIB_H
#define RESULT_SJDLIB_H

#pragma once
#include <cfloat>
#include <cstdint>
#include <utility>
#include <variant>
#include <iostream>

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef float f32;
typedef double f64;

void __assertion_failure(const char *msg, const char *file, unsigned line, const char *pretty_function) {
    std::cerr << "EQUALITY ASSERTION FAILED: " << msg << std::endl;
    std::cerr << file << ":" << line << " in " << pretty_function << std::endl;
    exit(1);
}

#define ASSERT(cond) \
    if (!(cond)) {      \
        __assertion_failure(#cond, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
    }

#define UNREACHABLE() ASSERT("unreachable" == NULL)

#define ASSERT_THROW(expr) \
    try {                  \
        (expr);            \
        __assertion_failure("Exception for '"#expr"' was not raised", __FILE__, __LINE__, __PRETTY_FUNCTION__); \
    } catch (...) {}       \

#define DEBUG(s) { std::cout << __FILE__ << "(" << __LINE__ << "): " << #s << " == " << s << std::endl; }
#define ERROR(s) { \
  const char *err = s; \
  std::cerr << __FILE__ << "(" << __LINE__ << "): error: " << (err != NULL ? err : "No error") << std::endl; \
}

typedef struct {
  char *buffer;
  size_t size;
} slice_t;

#define MARK() Mark mark(__PRETTY_FUNCTION__)

class Mark {
public:
    Mark(std::string function_pretty_name): _function_pretty_name(std::move(function_pretty_name)) {
        std::cout << this->_function_pretty_name << " begins" << std::endl;
    }

    ~Mark() {
        std::cout << this->_function_pretty_name << " ends" << std::endl;
    }

private:
    std::string _function_pretty_name;
};

template <typename T>
class Option {
public:
    static Option None() { return Option(); }

    Option() = default;

    explicit Option(T&& value): _has_value(true) {
        // placement new
        new (&this->storage) T(std::forward<T>(value));
    }

    T& value() {
        ASSERT(this->_has_value)
        // placement new
        return *reinterpret_cast<T*>(&this->storage);
    }

    bool has_value() noexcept { return this->_has_value; }

    Option& operator=(T&& value) {
        _has_value = true;
        new (&this->storage) T(std::forward<T>(value));
        return *this;
    }

    Option& operator=(T& value) {
        _has_value = true;
        new (&this->storage) T(std::move(value));
        return *this;
    }

private:
    alignas(T) u8 storage[sizeof(T)]{};
    bool _has_value = { false };
};

template <typename T, typename E>
class Result {
public:
    using ValueType = T;
    using ErrorType = E;

    static Result Ok(T& value) noexcept { return Result(value); }
    static Result Ok(const T& value) noexcept { return Result(value); }
    static Result Ok(T&& value) noexcept { return Result(std::forward<T&>(value)); }
    static Result Err(E& error) noexcept { return Result(error); }
    static Result Err(const E& error) noexcept { return Result(error); }
    static Result Err(E&& error) noexcept { return Result(std::forward<E&>(error)); }

public:
    T&& unwrap() {
        if (this->value.has_value()) {
            return std::move(this->value.value());
        }
        throw std::bad_variant_access();
    }

    T&& unwrap_or(T&& deflt) noexcept {
        if (this->value.has_value()) {
            return this->unwrap();
        }
        return deflt;
    }

    E&& err() noexcept {
        if (this->error.has_value()) {
            return std::move(this->error.value());
        }
        throw std::bad_variant_access();
    }

    bool is_ok() noexcept { return this->value.has_value(); }
    bool is_err() noexcept { return this->error.has_value(); }

    T&& operator!() {
        if (this->is_err()) {
            throw std::runtime_error(std::string(this->error.value()));
        }
        return this->unwrap();
    }

    Result<T, E>& otherwise(Result <T, E>& alternative) noexcept {
        if (this->value.value()) {
            return *this;
        }
        return alternative;
    }

private:
    explicit Result(T& value) {
        this->value = value;
    }

    explicit Result(E& error) {
        this->error = error;
    }


private:
    Option<T> value;
    Option<E> error;
};

#include <cstring>

extern "C" const char * const sys_errlist[];

Result<int, std::string> make_int_result(int value) {
    if (value < 0) {
        return Result<int, std::string>::Err(std::string(strerror(errno)));
    }
    return Result<int, std::string>::Ok(value);
}

template <typename T>
Result<T, std::string> make_ptr_result(T value) {
    static_assert(std::is_pointer<T>::value == true);
    if (value != nullptr) {
        return Result<int, std::string>::Err(std::string(sys_errlist[errno]));
    }
    return Result<int, std::string>::Ok(value);
}

#endif //RESULT_SJDLIB_H
