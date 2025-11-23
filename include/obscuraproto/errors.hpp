#ifndef OBSCURAPROTO_ERRORS_HPP
#define OBSCURAPROTO_ERRORS_HPP

#include <stdexcept>
#include <string>

namespace ObscuraProto {

/**
 * @brief Base class for all ObscuraProto exceptions.
 */
class Exception : public std::exception {
public:
    explicit Exception(const std::string& message) : msg_(message) {}
    explicit Exception(const char* message) : msg_(message) {}
    virtual ~Exception() noexcept override = default;

    virtual const char* what() const noexcept override {
        return msg_.c_str();
    }

protected:
    std::string msg_;
};

/**
 * @brief Exception for errors that occur at runtime.
 */
class RuntimeError : public Exception {
public:
    explicit RuntimeError(const std::string& message) : Exception(message) {}
    explicit RuntimeError(const char* message) : Exception(message) {}
};

/**
 * @brief Exception for logic errors in the library's usage.
 */
class LogicError : public Exception {
public:
    explicit LogicError(const std::string& message) : Exception(message) {}
    explicit LogicError(const char* message) : Exception(message) {}
};

/**
 * @brief Exception for invalid arguments.
 */
class InvalidArgument : public LogicError {
public:
    explicit InvalidArgument(const std::string& message) : LogicError(message) {}
    explicit InvalidArgument(const char* message) : LogicError(message) {}
};

} // namespace ObscuraProto

#endif // OBSCURAPROTO_ERRORS_HPP
