#pragma once

#include <bitset>
#include <iostream>
#include <string>
#include <vector>
#include "cxxopts.hpp"

class Config 
{
public:
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    // Static method to access the singleton instance
    static Config& getInstance() 
    {
        static Config instance;
        return instance;
    }

    void initialize(const cxxopts::ParseResult& result) 
    {
        m_inputFile  = result["input"].as<std::string>();
        if (result.count("showOB"))
            m_orderbook  = result["showOB"].as<std::vector<std::string>>();
        m_gaps       = m_options[0] = result["gaps"].as<bool>();
        m_msgSummary = m_options[1] = result["msgSummary"].as<bool>();
        m_time       = m_options[2] = result["time"].as<bool>();
        m_bbo        = m_options[3] = result["bbo"].as<bool>();
        m_arbitrage  = m_options[4] = result["arbitrage"].as<bool>();
        m_showOB     = m_options[5] = !m_orderbook.empty();
    }

    const std::string& getInputFile() const noexcept { return m_inputFile; }
    const std::vector<std::string>& orderbook() const noexcept { return m_orderbook; }
    bool gaps() const noexcept { return m_gaps; }
    bool msgSummary() const noexcept { return m_msgSummary;}
    bool time() const noexcept { return m_time; }
    bool bbo() const noexcept { return m_bbo; }
    bool arbitrage() const noexcept { return m_arbitrage; }
    bool showOB() const noexcept { return m_showOB; }
    bool gaps_or_msgSum_excl() const noexcept
    {
        if (m_gaps || m_msgSummary)
        {
            // if any of m_gaps or m_msgSummary is set then:
            // - return true if no other options is set (outside of those 2)
            // - return false if any other option is set
            auto bs = m_options;
            bs[0] = 0;
            bs[1] = 0;
            bs[2] = 0;

            return bs.any() ? false : true;    
        }
        return false;
    }

private:
    Config() : m_inputFile{}, m_orderbook{}, m_options{}, m_gaps{false}, 
        m_msgSummary{false}, m_time{false}, m_bbo{false}, m_arbitrage{false}, m_showOB{false} {}

private:
    std::string m_inputFile;
    std::vector<std::string> m_orderbook;
    std::bitset<6> m_options;
    bool m_gaps;
    bool m_msgSummary;
    bool m_time;
    bool m_bbo;
    bool m_arbitrage;
    bool m_showOB;
};

inline int handle_options(int argc, char* argv[])
{
    // Define and parse command-line options
        cxxopts::Options options("CBOEParser", "PCAP File Parser with Various Functionalities");
        options.add_options()
            ("input", "Input pcap file path", cxxopts::value<std::string>())
            ("bbo", "Enable BBO writer", cxxopts::value<bool>()->default_value("false"))
            ("gaps", "Enable Gaps Checker", cxxopts::value<bool>()->default_value("false"))
            ("msgSummary", "Enable Message Summary", cxxopts::value<bool>()->default_value("false"))
            ("arbitrage", "Enable the arbitrage finder", cxxopts::value<bool>()->default_value("false"))
            ("showOB", "Display an orderbook at a specific time", cxxopts::value<std::vector<std::string>>())
            ("t,time", "Display time", cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage");

        options.parse_positional({"input"});
        options.positional_help("input_file");

        // Customize help message to include positional arguments
        std::string usage = "Usage:\n  CBOEPcapParser [options] <input_file.pcap>";
        std::string example = "Example:\n  CBOEPcapParser --msgSummary --gaps --bbo ../path/to/file.pcap";

        auto result = options.parse(argc, argv);

        // Handle help option
        if (result.count("help")) 
        {
            std::cout << options.help() << std::endl;
            std::cout << example << std::endl;
            return 1;
        }

        if (!result.count("input")) 
        {
            std::cerr << "Input pcap file path is required.\n";
            std::cout << usage << std::endl;
            std::cout << example << std::endl;
            return 2;
        }

        if (result.count("showOB"))
        {
            auto showOB = result["showOB"].as<std::vector<std::string>>();

            if (showOB.size() != 3)
            {
                std::cerr << "Error: --showOB requires exactly 3 arguments: <symbol>,<YYYY-MM-DD>,<HH::MM::SS.nnnnnnnnn>\n";
                std::cout << "Example:\n  CBOEPcapParser --showOB=VXV4,2024-10-09,03:40:50.092210000 ../path/to/file.pcap";
                return 3; // Exit with error code
            }
        }

        // Initialize the Config singleton with parsed options
        Config::getInstance().initialize(result);

        return 0;
}
