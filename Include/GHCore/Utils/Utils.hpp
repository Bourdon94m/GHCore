#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <mutex>
#include <cstdint>
#include <chrono>
#include <ctime>

namespace GHCore::Utils {

// ── Logger ────────────────────────────────────────────────────────────────────

enum class LogLevel { Debug, Info, Warning, Error };

class Logger {
public:
    static Logger& Get() {
        static Logger inst;
        return inst;
    }

    // Open a dedicated console window (useful when injected as a DLL)
    void AllocConsole(const std::string& title = "GHCore") {
        ::AllocConsole();
        SetConsoleTitleA(title.c_str());
        freopen_s(&m_cout, "CONOUT$", "w", stdout);
        freopen_s(&m_cerr, "CONOUT$", "w", stderr);
        m_hasConsole = true;
    }

    void OpenFile(const std::string& path) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_file.open(path, std::ios::out | std::ios::app);
    }

    void SetMinLevel(LogLevel level) { m_minLevel = level; }

    void Log(LogLevel level, const std::string& msg) {
        if (level < m_minLevel) return;
        std::lock_guard<std::mutex> lk(m_mtx);
        std::string line = Format(level, msg);
        if (m_hasConsole) {
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(h, ConsoleColor(level));
            printf("%s\n", line.c_str());
            SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        if (m_file.is_open()) m_file << line << '\n';
    }

    void Debug(const std::string& m)   { Log(LogLevel::Debug,   m); }
    void Info(const std::string& m)    { Log(LogLevel::Info,    m); }
    void Warning(const std::string& m) { Log(LogLevel::Warning, m); }
    void Error(const std::string& m)   { Log(LogLevel::Error,   m); }

    ~Logger() {
        if (m_file.is_open()) m_file.close();
        if (m_cout) fclose(m_cout);
        if (m_cerr) fclose(m_cerr);
    }

private:
    Logger() = default;

    static std::string Format(LogLevel level, const std::string& msg) {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        tm tm_buf{};
        localtime_s(&tm_buf, &time);
        std::ostringstream oss;
        oss << '[' << std::put_time(&tm_buf, "%H:%M:%S") << ']'
            << '[' << LevelStr(level) << "] " << msg;
        return oss.str();
    }

    static const char* LevelStr(LogLevel l) {
        switch (l) {
            case LogLevel::Debug:   return "DBG";
            case LogLevel::Info:    return "INF";
            case LogLevel::Warning: return "WRN";
            case LogLevel::Error:   return "ERR";
        }
        return "???";
    }

    static WORD ConsoleColor(LogLevel l) {
        switch (l) {
            case LogLevel::Debug:   return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
            case LogLevel::Info:    return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            case LogLevel::Warning: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            case LogLevel::Error:   return FOREGROUND_RED | FOREGROUND_INTENSITY;
        }
        return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }

    std::mutex    m_mtx;
    std::ofstream m_file;
    FILE*         m_cout     = nullptr;
    FILE*         m_cerr     = nullptr;
    bool          m_hasConsole = false;
    LogLevel      m_minLevel = LogLevel::Debug;
};

#define GHCORE_LOG_DBG(m)  GHCore::Utils::Logger::Get().Debug(m)
#define GHCORE_LOG_INFO(m) GHCore::Utils::Logger::Get().Info(m)
#define GHCORE_LOG_WARN(m) GHCore::Utils::Logger::Get().Warning(m)
#define GHCORE_LOG_ERR(m)  GHCore::Utils::Logger::Get().Error(m)

// ── Timer ─────────────────────────────────────────────────────────────────────

class Timer {
public:
    void  Reset()      { m_start = Clock::now(); }
    float ElapsedMs()  const { return std::chrono::duration<float, std::milli>(Clock::now() - m_start).count(); }
    float ElapsedSec() const { return ElapsedMs() / 1000.f; }
private:
    using Clock = std::chrono::high_resolution_clock;
    Clock::time_point m_start = Clock::now();
};

// ── Address / byte helpers ────────────────────────────────────────────────────

inline std::string ToHex(uintptr_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << addr;
    return oss.str();
}

inline std::string BytesToHex(const uint8_t* data, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i) {
        if (i) oss << ' ';
        oss << std::uppercase << std::hex
            << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

// ── Color RGBA ────────────────────────────────────────────────────────────────

struct Color {
    uint8_t r = 255, g = 255, b = 255, a = 255;

    Color() = default;
    Color(uint8_t r, uint8_t g, uint8_t b, uint8_t a = 255) : r(r), g(g), b(b), a(a) {}

    static Color FromARGB(uint32_t argb) {
        return { uint8_t(argb >> 16), uint8_t(argb >> 8), uint8_t(argb), uint8_t(argb >> 24) };
    }
    uint32_t ToARGB() const {
        return (uint32_t(a) << 24) | (uint32_t(r) << 16) | (uint32_t(g) << 8) | r;
    }

    static Color Red()    { return {255,   0,   0}; }
    static Color Green()  { return {  0, 255,   0}; }
    static Color Blue()   { return {  0,   0, 255}; }
    static Color White()  { return {255, 255, 255}; }
    static Color Yellow() { return {255, 255,   0}; }
};

} // namespace GHCore::Utils
