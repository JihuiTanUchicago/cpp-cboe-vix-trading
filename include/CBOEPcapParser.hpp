#pragma once

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <pcap.h>
#include <unordered_map>
#include <stdexcept>
#include <chrono>

#include "cfepitch.h"
#include "DataExporter.hpp"
#include "MessageInfo.hpp"
#include "OrderBookManager.hpp"
#include "OrderStore.hpp"
#include "OrderBook.hpp"
#include "StopWatch.hpp"

// Global variables
class CBOEPcapParser
{
  public:
    explicit CBOEPcapParser(const std::string& filename, std::size_t id);
    CBOEPcapParser(const CBOEPcapParser& other) = delete;
    void operator=(const CBOEPcapParser& other) = delete;

    void start(); // Start processing the pcap file
    void messages_summary();

  private:
    void process_message(uint64_t pktSeqNum, uint64_t msgSeqNum, const u_char *message, int msg_type); // Process a single message
    void process_packet(const u_char *packet) noexcept; // Process a single packet from a PCAP file
    void gap_helper(const u_char *packet) noexcept;
    void messages_summary_helper(const u_char *packet) noexcept;

  private:
    std::string m_pcapFilename;         // Input pcap file
    std::size_t m_id;
    MessageInfo m_messageInfo;          // Messages information
    OrderStore m_orderstore;            // Order store
    DataExporter m_dataExporter;        // Data exporter
    OrderBookManager m_obm;             // Order book manager
};

class PcapSlicer
{
  public:
    PcapSlicer(const std::string& filename);
    std::string slice_pcap(const std::string& begin_time, const std::string& end_time, const std::string& output_filename = "output.pcap");
    void daily_slice();

  private:
    std::string m_pcapFilename;
    uint32_t m_gNextExpectedPacketSeqNum = 1;
    std::size_t m_dayCount;
};