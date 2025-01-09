// StopWatch.cpp
// 
// Implementation Stopwacth.hpp
// 

#include <iostream>

#include "StopWatch.hpp"

using Clock = std::chrono::high_resolution_clock;

StopWatch::StopWatch()
	: m_name{}, m_startTimePoint{ Clock::now() }, m_endTimePoint{ m_startTimePoint }, m_duration{}, m_isRunning{ false }
{}

StopWatch::StopWatch(const std::string& name)
	: m_name{name}, m_startTimePoint{ Clock::now() }, m_endTimePoint{ m_startTimePoint }, m_duration{}, m_isRunning{ false }
{}

void StopWatch::Start()
{
	if (!m_isRunning)
	{
		m_startTimePoint = Clock::now();
		m_isRunning = true;
	}
	// Does nothing if stopwatch is already running
}

void StopWatch::set_name(const std::string& name)
{
	m_name = name;
}

void StopWatch::Stop()
{
	if (m_isRunning)
	{
		m_endTimePoint = Clock::now();
		std::chrono::duration<double> elapsed_time = m_endTimePoint - m_startTimePoint;
		m_duration += elapsed_time.count();
		m_isRunning = false;
	}
	// Does nothing if stopwatch is not running
}

void StopWatch::Reset()
{
	m_startTimePoint = Clock::now();
	m_endTimePoint = m_startTimePoint;
	m_duration = 0.0;
}

double StopWatch::GetTime() const
{
	if (m_isRunning)
	{
		std::chrono::duration<double> elapsed_time = Clock::now() - m_startTimePoint;
		return elapsed_time.count() + m_duration;
	}

	return m_duration;
}

void StopWatch::display_time() const
{
	std::cout << m_name << " - " << m_duration << "s\n";
}