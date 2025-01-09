// Compile: Run "CMake: Configure" in the VSCode Command Palette
//          cmake --build build

#include <iostream>
#include <sstream>
#include <filesystem>
#include <cstdlib>  
#include <thread>

#include "CBOEPcapParser.hpp"
#include "Config.hpp"
#include "cxxopts.hpp"
#include "OrderBook.hpp"
#include "OrderBookManager.hpp"
#include "OrderStore.hpp"
#include "StopWatch.hpp"

void init(std::size_t day)
{
    std::string input_filename = "../day" + std::to_string(day) + ".pcap";
    CBOEPcapParser pcap_parser(input_filename, day);
    pcap_parser.start();
}
   
int main(int argc, char* argv[])
{
    int error_code = handle_options(argc, argv);

    if (error_code)
        return error_code;

    try
    {   
        auto& config = Config::getInstance();

        StopWatch sw;
        if (config.time())
        {
            sw.set_name("Total Time");
            sw.Start();
        }

        StopWatch swGapsSmry;
        if (config.msgSummary() || config.gaps())
        {
            if (config.time())
            {
                swGapsSmry.set_name("Gaps and/or Message Summary Time");
                swGapsSmry.Start();
            }
            CBOEPcapParser parser{config.getInputFile(), 0};
            parser.messages_summary();

            swGapsSmry.Stop();
            if (config.gaps_or_msgSum_excl())
            {
                swGapsSmry.display_time();
                return 0;
            }
        }

        StopWatch swSlice;
        {
            if (config.time())
            {
                swSlice.set_name("Slicing Time");
                swSlice.Start();
            }

            PcapSlicer slicer(config.getInputFile());
            slicer.daily_slice();

            swSlice.Stop();
        }

        {
            std::vector<std::thread> threads{};

            for (std::size_t i = 1; i <= 5; ++i)
            {
                threads.emplace_back(init, i);
            }

            for (auto& t : threads) 
            {
                if (t.joinable()) 
                {
                    t.join();
                }
            }
        }

        sw.Stop();
        swGapsSmry.display_time();
        swSlice.display_time();
        sw.display_time();
    }
    catch(const cxxopts::exceptions::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    catch(const std::exception& e)
    {
        std::cerr << "ERROR: " << e.what() << '\n';
    }

    return 0;
}

