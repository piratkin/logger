#pragma once
#include "flags.h"
#include <cstdint> /* uint32_t */
#include <mutex> /* mutex recursive_mutex unique_lock scoped_lock */
#include <map> /* map multimap erase_if */
#include <string> /* string */
#include <memory> /* shared_ptr */
#include <filesystem> /* path is_regular_file remove rename exists weakly_canonical create_directories */
#include <fstream> /* fstream ofstream */
#include <any> /* any any_cast */
#include <list> /* list */
#include <thread> /* jthread */
#include <condition_variable> /* condition_variable */
#include <optional> /* optional */
#include <functional> /* function bind */
#include <iostream> /* cerr cout ostream */
#include <sstream> /* stringstream */
#include <source_location> /* source_location current */
#include <tuple> /* tuple */
#include <fmt/core.h>
#include <fmt/chrono.h>
#include <fmt/color.h> /* fmt::color */
#include <fmt/printf.h> /* fmt::sprntf */
#include <fmt/format.h> /* fmt::format */

#define LOGGER_FORMAT_PRINT(S, F) \
template <class... Args> \
void S(const Location& info, Args&&... args) { \
    _print(ELevel::F, info.src, \
        fmt::vformat(info.format, fmt::make_format_args( \
            std::forward<Args>(args)...))); \
}

#define LOGGER_SPRINT_PRINT(N) \
template <class... Args> \
void N(const Location& info, Args&&... args) { \
    _print(ELevel::N, info.src, \
        fmt::sprintf(info.format, args...)); \
}

#define LOGGER_STREAM_PRINT(N) \
Stream& N(const std::source_location& src = \
    std::source_location::current()) { \
    static Stream N(ELevel::N, this); \
    return N.take(src); \
}

#define LOGGER_PRINT(S, F) \
LOGGER_FORMAT_PRINT(S, F) \
LOGGER_SPRINT_PRINT(F) \
LOGGER_STREAM_PRINT(F)

enum class ELevel : uint8_t {
    none = 0,
    /* stderr: */
    fatal, error,
    /* stdout: */
    warn, info,
    debug, trace,
};

DECLARE_string(PROGECT_NAME);
Flags SIZE_LIMIT("size", 1048576ULL, [](auto v) { return v > 1024ULL; });
Flags DEPTH_LIMIT("depth", 10U, [](auto v) { return v < 100U; });
Flags ERROR_LEVEL("level", 3U, [](auto v) { return v < 7U; });
Flags SYSLOG_FLAG("fsyslog", false);
Flags SYSOUT_FLAG("fsysout", true);
Flags COLOR_FLAG("fcolor", true);
Flags COLOR_NONE("color-none",   0xffffffU);
Flags COLOR_FATAL("color-fatal", 0xff00ffU);
Flags COLOR_ERROR("color-error", 0xff4500U);
Flags COLOR_WARN("color-warn",   0xffff00U);
Flags COLOR_INFO("color-info",   0x00ff00U);
Flags COLOR_DEBUG("color-debug", 0x1ca099U);
Flags COLOR_TRACE("color-trace", 0x808080U);

class Location {
public:
    std::string_view format;
    std::source_location src;
    Location(const char* format, 
        const std::source_location& src =
            std::source_location::current()) noexcept
    : format(format), src(src) {}
};

inline std::map<const ELevel, const std::tuple<const std::string,
    const unsigned* const>> infolevel {
    {ELevel::none,  {"NONE ", &COLOR_NONE()}},
    {ELevel::fatal, {"FATAL", &COLOR_FATAL()}},
    {ELevel::error, {"ERROR", &COLOR_ERROR()}},
    {ELevel::warn,  {"WARN ", &COLOR_WARN()}},
    {ELevel::info,  {"INFO ", &COLOR_INFO()}},
    {ELevel::debug, {"DEBUG", &COLOR_DEBUG()}},
    {ELevel::trace, {"TRACE", &COLOR_TRACE()}},
};

#ifdef __linux__
#include <syslog.h>
inline std::map<const ELevel,
    const int> syslevel{
    {ELevel::none,  LOG_EMERG},
    {ELevel::fatal, LOG_CRIT},
    {ELevel::error, LOG_ERR},
    {ELevel::warn,  LOG_WARNING},
    {ELevel::info,  LOG_NOTICE},
    {ELevel::debug, LOG_INFO},
    {ELevel::trace, LOG_DEBUG},
};
#else
#include <windows.h>
inline std::map<const ELevel, 
    const uint16_t> syslevel { 
    {ELevel::none,  EVENTLOG_SUCCESS},
    {ELevel::fatal, EVENTLOG_ERROR_TYPE}, 
    {ELevel::error, EVENTLOG_ERROR_TYPE}, 
    {ELevel::warn,  EVENTLOG_WARNING_TYPE},
    {ELevel::info,  EVENTLOG_INFORMATION_TYPE}, 
    {ELevel::debug, EVENTLOG_SUCCESS}, 
    {ELevel::trace, EVENTLOG_SUCCESS},
};
#endif

enum class LoggerId : uint8_t {
    level,  /* Logger error level */
    size,   /* Logger size limit in bytes */
    depth,  /* Logrotate limit */
    syslog, /* Print into syslog */
    sysout, /* Print into stdout stderr */
    color,  /* Colored console output */
};

/* Streamp pool */
class StreamPool {
public:
    std::fstream stream;
    size_t size;
    size_t depth; 
    size_t _size;
};

/* logger pool */
class LoggerPool {
public:
#ifndef __linux__
    HANDLE handle;
#endif
    ELevel level;
    std::optional<std::string> key;
    bool is_sysout;
    bool is_syslog;
    bool is_color;
};

class ILogger {
public:
    virtual void _print(
        const ELevel level, 
        const std::source_location& src,
        const std::string message) = 0;
protected:
    virtual ~ILogger() {}
};

class Stream {
    ELevel level;
    std::source_location src;
    std::stringstream ss;
    ILogger* ptr = nullptr;
    
public:
    Stream(const ELevel level, 
        ILogger* ptr = nullptr)
        : ptr(ptr), level(level) {}
    Stream& take(
        const std::source_location& src) {
        this->src = src;
        return *this;
    }
    template<typename T>
    Stream& operator<<(T&& rhs) {
        if (ptr != nullptr) ss << rhs;
        return *this;       
    }
    Stream& operator<<(std::ostream&(*rhs)(std::ostream&)) {
        if (ptr != nullptr)
            ptr->_print(level, src, ss.str());
        std::stringstream _ss;
        ss.swap(_ss);
        return *this;
    }
};

class Logger : public ILogger {
    inline static std::mutex _e;
    inline static std::recursive_mutex _m;
    inline static std::jthread _worker;
    inline static std::condition_variable _event;
    inline static std::list<std::function<void()>> _queue;
    inline static std::multimap<std::string,
        std::shared_ptr<StreamPool>> _cache;
    std::shared_ptr<LoggerPool> _pool;
    
    inline void _make_pool(
        const std::string& key, 
        std::shared_ptr<StreamPool> pool) noexcept {
        using std::filesystem::is_regular_file;
        using std::filesystem::file_size;
        using std::filesystem::path;
        size_t _size = 0;
        if (path file = key;
            is_regular_file(file) == true) {
            _size = file_size(file);
        }
        if (pool.get() == nullptr) {
            pool = std::shared_ptr<StreamPool>(
                new StreamPool {
                    .stream = std::fstream(key,
                        std::fstream::app |
                        std::fstream::in |
                        std::fstream::out),
                    .size = SIZE_LIMIT(),
                    .depth = DEPTH_LIMIT(),
                    ._size = _size,
                }, [] (StreamPool* ptr) noexcept {
                    ptr->stream.flush();
                    ptr->stream.close();
                    Logger::_event.notify_all();
                    delete ptr;
                }
            );
        }
        _cache.emplace(key, pool);
    }
    
    inline void _rotate(
        const std::shared_ptr<StreamPool>& sp, 
        const std::string& key) {
        using std::filesystem::path;
        using std::filesystem::exists;
        using std::filesystem::rename;
        using std::filesystem::remove;
        using std::filesystem::is_regular_file;
        using std::filesystem::recursive_directory_iterator;
        path file = key;
        if (is_regular_file(file) == false ||
            file.has_parent_path() == false) {
            return;
        }
        path prev = key + ".-1";
        path next = key + ".0";
        std::error_code ec;
        if (is_regular_file(next) == false) {
            /* Copy file into <name>.-1 */
            std::fstream out(prev, 
                std::fstream::out | 
                std::fstream::trunc);
            if (out.is_open() == false) {
                return;
            }
            sp->stream.flush();
            sp->stream.seekg(0, std::ios::beg);
            out << sp->stream.rdbuf();
            sp->stream.seekg(0, std::ios::end);
            out.close();
            /* Rename file to <name>.0 */
            if (rename(prev, next, ec); ec) {
                return;
            }
        }
        /* Clean current file */
        std::fstream out(
            key.c_str(),
            std::fstream::out |
            std::fstream::trunc);
        if (out.is_open() == false) {
            return;
        }
        out.close();
        sp->_size = 0;
        /* Remove N file if exists */
        file = key + "." + std::to_string(sp->depth);
        if (exists(file) == true) {
            if (is_regular_file(file) == false ||
                remove(file, ec) == false) {
                return;
            }
        }
        /* Rotate files */
        for (int i = 1; i > 0 && i <= sp->depth;) {
            prev = key + "." + std::to_string(i - 1);
            next = key + "." + std::to_string(i);
            if (exists(next) == true) {
                ++i;
            } else if (rename(prev, next, ec); !ec) {
                --i;
            } else {
                return;
            }
        }
    }    
    
    inline static std::list<std::function<void()>> _read() noexcept {
        std::list<std::function<void()>> buffer(0);
        std::unique_lock<std::mutex> elock(Logger::_e);
        using namespace std::chrono_literals;
        Logger::_event.wait_for(elock, 1s);
        std::scoped_lock<std::recursive_mutex> lock(Logger::_m);
        buffer.swap(Logger::_queue);
        return buffer;
    }
    
    inline static void _make_thread() noexcept { 
        Logger::_worker = std::jthread([](std::stop_token token) {
            while (token.stop_requested() == false) {
                for(auto&& exec : Logger::_read()) {
                    exec();
                }
            }
        });
    }

    void _sysprint(const ELevel level,
        const std::string& message) {
#ifdef __linux__
        syslog(syslevel[level],
            message.c_str());
#else
        if (_pool->handle == INVALID_HANDLE_VALUE) {
            return;
        }
        LPCSTR _message { 
            const_cast<char*>(message.c_str())
        };
        ReportEventA(_pool->handle,
            syslevel[level],
            0U, 0U, nullptr, 1, 0U,
            &_message,
            nullptr);
#endif
    }

    void _print(const ELevel level, 
        const std::source_location& src,
        const std::string message) {
        if (level > _pool->level) {
            return;
        }
        if (_pool->is_syslog == true) {
            _sysprint(level, message);
        }
        using std::filesystem::path;
        auto time = std::chrono::system_clock::now();
        std::string name = src.file_name();
        if (path file = name;
            file.has_stem()) {
            name = file.stem().string();
        }
        auto&& [strlevel, colorlevel] = infolevel[level];
        std::string buffer = fmt::format(
            "\n{:%F} {:%H:%M:%S} {:s} [{:s}@{:d}] {:s}", 
            time, std::chrono::round<
                std::chrono::milliseconds>(time.time_since_epoch()),
            strlevel, name, src.line(), message);
        auto format = [&] () -> std::string {
            if (_pool->is_color == false) return buffer;
            return fmt::format(fmt::fg(
                static_cast<fmt::color>(*colorlevel)), 
                    buffer);
        };
        if (_pool->is_sysout == true) {
            switch (level) {
            case ELevel::fatal:
                std::cerr << format();
                std::cout.flush();
                exit(EXIT_FAILURE);
            case ELevel::error:
                std::cerr << format();
                break;
            case ELevel::warn:
            case ELevel::info:
            case ELevel::debug:
            default:
                std::cout << format()
                    << std::flush;
                break;
            }
        }
        if (_pool->key.has_value() == false) {
            return;
        }
        auto it = Logger::_cache.find(_pool->key.value());
        if (it == Logger::_cache.end()) {
            return;
        }

        auto printer = [&](std::string message,
            std::shared_ptr<LoggerPool> lp,
            std::shared_ptr<StreamPool> sp) {
            if (sp != nullptr &&
                sp->stream.is_open() == true) {
                sp->stream << message << std::flush;
                sp->_size += message.size();
            }
            if (lp != nullptr &&
                lp->key.has_value() == true &&
                sp->size > 0 &&
                sp->_size > sp->size) {
                _rotate(sp, lp->key.value());
            }
        };
        auto task = std::bind(printer, buffer, _pool, it->second);
        std::scoped_lock<std::recursive_mutex> lock(Logger::_m);
        Logger::_queue.emplace_back(task);
    }

public:

    inline bool set(LoggerId id, std::any value) noexcept {
        if (value.has_value() == false) {
            return false;
        }
        auto _set = [&] {
            std::scoped_lock<std::recursive_mutex> lock(Logger::_m);
            /* Local config */
            switch (id) {
            case LoggerId::level:
                _pool->level = std::any_cast<ELevel>(value);
                if (_pool->level > ELevel::trace) {
                    _pool->level = ELevel::trace;
                }
                return true;
            case LoggerId::syslog:
                _pool->is_syslog = std::any_cast<bool>(value);
                if (_pool->is_syslog == true) {
#ifdef __linux__
                    openlog(PROGECT_NAME().c_str(), LOG_PID, LOG_USER);
#else
                    _pool->handle = _pool->handle == INVALID_HANDLE_VALUE
                        ? ::OpenEventLogA(nullptr, 
                            LPCSTR{ PROGECT_NAME().c_str() })
                        : _pool->handle;
#endif
                }
                return true;
            case LoggerId::sysout:
                _pool->is_sysout = std::any_cast<bool>(value);
                return true;
            case LoggerId::color:
                _pool->is_color = std::any_cast<bool>(value);
                return true;
            }
            /* Global config */
            if (_pool->key.has_value() == false) {
                return false;
            }
            auto it = Logger::_cache.find(_pool->key.value());
            if (it == Logger::_cache.end()) {
                return false;
            }
            auto ptr = it->second.get();
            switch (id) {
            case LoggerId::size:
                ptr->size = std::any_cast<size_t>(value);
                return true;
            case LoggerId::depth:
                ptr->depth = std::any_cast<size_t>(value);
                return true;
            }
            return false;     
        };
        try {
            return _set();
        } catch (const std::exception& e) {
            error(e.what());
        }
        return false;
    }

    Logger(ELevel level = ELevel::warn,
        bool is_syslog = SYSLOG_FLAG(),
        bool is_sysout = SYSOUT_FLAG(),
        bool is_color = COLOR_FLAG()) {
        _pool = std::make_shared<LoggerPool>(
#ifndef __linux__
            INVALID_HANDLE_VALUE,
#endif
            level, std::nullopt, 
            is_sysout, is_syslog, 
            is_color);
        set(LoggerId::syslog, is_syslog);

    }

    Logger(std::filesystem::path file, 
        ELevel level = ELevel::warn, 
        bool is_syslog = SYSLOG_FLAG(),
        bool is_sysout = SYSOUT_FLAG(),
        bool is_color = COLOR_FLAG())
        : Logger(level, is_syslog, is_sysout) {
        std::error_code ec;
        if (std::filesystem::path dir = file.parent_path();
            std::filesystem::is_regular_file(file) ||
            std::filesystem::exists(dir) ||
            std::filesystem::create_directories(dir, ec)) {            
            file = std::filesystem::weakly_canonical(file);
        } else {
            error("Unable use `%s` file",
                file.generic_string());
        }
        _pool->key = file.generic_string();
        std::shared_ptr<StreamPool> sp = nullptr;
        std::unique_lock<std::recursive_mutex> lock(Logger::_m);
        if (_worker.joinable() == false) {
            _make_thread();
        }
        if (auto it = Logger::_cache.find(_pool->key.value());
            it != Logger::_cache.end()) {
            sp = it->second;
        }
        _make_pool(_pool->key.value(), sp);
    }
    
    ~Logger() noexcept {
        /* Key not exists */
        if (_pool->key.has_value() == false ||
            Logger::_cache.contains(_pool->key.value()) == false) {
            return;
        }
        /* Clen cache */
        if (std::scoped_lock<std::recursive_mutex> lock(Logger::_m);
            Logger::_cache.size() > 1) {
            auto it = Logger::_cache.find(_pool->key.value());
            Logger::_cache.erase(it);
            return;
        }
        /* Wait for all the work to be done */
        if (Logger::_worker.joinable() == true &&
            Logger::_worker.request_stop() == true) {
            Logger::_worker.join();
        }
    }
    
    LOGGER_PRINT(f, fatal)
    LOGGER_PRINT(e, error)
    LOGGER_PRINT(w, warn)
    LOGGER_PRINT(i, info)
    LOGGER_PRINT(d, debug)
    LOGGER_PRINT(t, trace)

};