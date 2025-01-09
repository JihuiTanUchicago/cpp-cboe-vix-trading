#pragma once

#include <vector>
#include <thread>
#include <functional>
#include <queue>
#include <mutex>
#include <future>
#include <condition_variable>

class ThreadPool
{
public:
    using Task = std::move_only_function<void()>;

public:
    explicit ThreadPool(size_t numWorkers);
    ~ThreadPool();

    void wait_all_done();

    template<typename F, typename... Args>
    void enqueue(F&& function, Args&&... args)
    {
        using ReturnType = std::invoke_result_t<F, Args...>;

        auto packt = std::packaged_task<ReturnType()>
        { 
            std::bind_front(std::forward<F>(function), std::forward<Args>(args)...) 
        };

        Task task{ [packt = std::move(packt)]() mutable { packt(); } };
        {
            std::lock_guard lk{ m_taskQueueMtx };
            m_tasks.push(std::move(task));
        }
        m_taskQueueCV.notify_one();
    } 

private:
    class Worker_
    {
    public:
        explicit Worker_(ThreadPool* pool);
        Worker_(const Worker_&) = delete;                 // Disable copying
        Worker_& operator=(const Worker_&) = delete;      // Disable copy assignment
        Worker_(Worker_&&) noexcept = default;           
        Worker_& operator=(Worker_&&) noexcept = default; 

        void request_stop();

    private:
        void run_task(std::stop_token st);
    
    private:
        ThreadPool* m_pool;
        std::jthread m_thread;
    };

private:
    Task dequeue(std::stop_token& st);

private:
    std::queue<Task> m_tasks;
    std::vector<Worker_> m_workers;
    std::mutex m_taskQueueMtx;
    std::condition_variable_any m_taskQueueCV;
    std::condition_variable m_allDoneCV;
};
