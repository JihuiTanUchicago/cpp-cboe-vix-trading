#include <vector>
#include <thread>
#include <functional>
#include <deque>
#include <mutex>
#include <future>
#include <condition_variable>

#include "ThreadPool.hpp"

ThreadPool::ThreadPool(size_t numWorkers)
{
    m_workers.reserve(numWorkers);
    for (size_t i = 0; i < numWorkers; ++i) 
    {
        m_workers.emplace_back(this); // Push the the given number of worker threads to the thread pool
    }
}

ThreadPool::~ThreadPool()
{
    for (auto& worker : m_workers) 
    {
        worker.request_stop(); // Stops all the threads
    }
}

void ThreadPool::wait_all_done()
{
    std::unique_lock<std::mutex> lock(m_taskQueueMtx);
    m_allDoneCV.wait(lock, [this] { return m_tasks.empty(); }); // Wait for all workers to empty the task queue
}

ThreadPool::Task ThreadPool::dequeue(std::stop_token& st)
{
    Task task;
    std::unique_lock<std::mutex> lock(m_taskQueueMtx);

    // If queue is empty, current thread waits until a new task is added to the queue or until the stop token is triggered
    // Added a predicate that checks if the queue is indeed empty to prevent spurious wake-ups
    m_taskQueueCV.wait(lock, st, [this] { return !m_tasks.empty(); });
    if (!st.stop_requested()) 
    {
        task = std::move(m_tasks.front());
        m_tasks.pop();
        if (m_tasks.empty()) 
        {
            m_allDoneCV.notify_all(); // Notify when all tasks are done
        }
    }

    return task;
}

// ---------------- Worker Thread ----------------

ThreadPool::Worker_::Worker_(ThreadPool* pool) 
    : m_pool(pool), m_thread(std::bind_front(&Worker_::run_task, this)) // Binds the current object's member function run_task() to the jthread
{}

void ThreadPool::Worker_::request_stop()
{
    m_thread.request_stop(); // Signal thread to stop
}

void ThreadPool::Worker_::run_task(std::stop_token st)
{
    while (auto task = m_pool->dequeue(st)) 
    {
        task(); // Execute the task
    }
}


