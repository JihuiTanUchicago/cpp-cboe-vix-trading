// StopWatch.hpp
// 
// Simple timer to record duration
// 

#pragma once

#include <chrono>

// StopWatch where start and stop can be manually set
class StopWatch
{
public:
    StopWatch();
	explicit StopWatch(const std::string& name);
	StopWatch(const StopWatch&) = delete;
	StopWatch& operator=(const StopWatch&) = delete;

	void Start();
	void Stop();
	void Reset();
    void set_name(const std::string& name);

	double GetTime() const;
    void display_time() const;

private:
    std::string m_name;
	std::chrono::time_point<std::chrono::high_resolution_clock> m_startTimePoint;
	std::chrono::time_point<std::chrono::high_resolution_clock> m_endTimePoint;
	double m_duration;
	bool m_isRunning = false;
};

// Timer 
#include <iostream>
#include <chrono>
#include <string_view>

class Timer {
public:
    Timer() { Reset(); }
    
    void Reset() { m_Start = std::chrono::high_resolution_clock::now(); }
    
    // Elapsed time in seconds
    float Elapsed() const {
        return std::chrono::duration<float>(std::chrono::high_resolution_clock::now() - m_Start).count();
    }

    // Elapsed time in milliseconds
    float ElapsedMillis() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - m_Start).count();
    }

    // Elapsed time in microseconds
    float ElapsedMicros() const {
        return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - m_Start).count();
    }

    // Elapsed time in nanoseconds
    float ElapsedNanos() const {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - m_Start).count();
    }

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_Start;
};

class ScopedTimer {
public:
    ScopedTimer(std::string_view name) : m_Name(name) {}
    
    ~ScopedTimer() {
        float time = m_Timer.Elapsed(); // Elapsed time in nanoseconds
        std::cout << m_Name << " - " << time << "s\n";
    }

private:
    Timer m_Timer;
    std::string m_Name;
};
