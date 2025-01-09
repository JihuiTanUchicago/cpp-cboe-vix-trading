#include <filesystem>
#include <format>
#include <regex>
#include <sstream>
#include <pcap.h>
#include <iostream>
#include <functional>
#include <cstring>

#include "CBOEPcapParser.hpp"
#include "cfepitch.h"
#include "Config.hpp"
#include "MessageInfo.hpp"
#include "Order.hpp"
#include "OrderBookManager.hpp"
#include "OrderStore.hpp"
#include "OrderBook.hpp"
#include "DataExporter.hpp"
#include "StopWatch.hpp"
#include "Symbol.hpp"

CBOEPcapParser::CBOEPcapParser(const std::string& filename, std::size_t id)
    : m_pcapFilename{filename}, m_id{id}, m_messageInfo{}, m_orderstore{}, 
    m_dataExporter{m_id}, m_obm{&m_orderstore, &m_dataExporter}
{
    m_dataExporter.set_obm(&m_obm);
}

void CBOEPcapParser::process_message(uint64_t pktSeqNum, uint64_t msgSeqNum, const u_char *message, int msg_type)
{
    switch (msg_type)
    {
        // NON-ORDER MESSAGES
        // The following message types do not alter book state.  They may be used
        // for information purposes in some Feedhandler implementations, or may be
        // ignored altogether in other, minimalistic, implementations.

        case 0x20: // Time
        {
            Time m = *(Time*)message;
            m_dataExporter.set_time_ref(m.Time);

            break;
        }

        [[unlikely]] case 0x97: // UnitClear
        {
            break;
        }

        case 0xB1: // TimeReference
        {
            TimeReference m = *(TimeReference*)message;
        
            // Parse the midnight reference date(YYYYMMDD)            
            m_dataExporter.set_date(m.MidnightReference);
        
            break;
        }

        case 0xBB: // FuturesInstrumentDefinition
        {
            FuturesInstrumentDefinition m = *(FuturesInstrumentDefinition*)message;
            Symbol symbol(m.Symbol);

            m_obm.add_orderbook(symbol, m.ContractSize, m.PriceIncrement);
            // Pass the symbol to the data exporter for conversion to human-readable symbol
            m_dataExporter.symbol_tostring(symbol, m, message);
            break;
        }

        case 0xBE: // PriceLimits
        {
            // PriceLimits m = *(PriceLimits*)message;
            break;
        }

        case 0xBC: // TransactionBegin
        {
            // TransactionBegin m = *(TransactionBegin*)message;
            break;
        }

        case 0xBD: // TransactionEnd
        {
            // TransactionEnd m = *(TransactionEnd*)message;
            break;
        }

        case 0x31: // TradingStatus
        {
            TradingStatus m = *(TradingStatus*)message;
            m_obm.update_tradingStatus(m.Symbol, m.TradingStatus);
            break;
        }

        case 0x2A: // TradeLong
        {
            // TradeLong m = *(TradeLong*)message;
            break;
        }
        case 0x2B: // TradeShort
        {
            // TradeShort m = *(TradeShort*)message;
            break;
        }

        case 0x2C: // TradeBreak
        {
            // TradeBreak m = *(TradeBreak*)message;
            break;
        }

        case 0xB9: // Settlement
        {
            // Settlement m = *(Settlement*)message;
            break;
        }

        case 0xD3: // OpenInterest
        {
            // OpenInterest m = *(OpenInterest*)message;
            break;
        }

        case 0xBA: // EndOfDaySummary
        {
            // EndOfDaySummary m = *(EndOfDaySummary*)message;
            break;
        }

        case 0x2D: // EndOfSession
        {
            // EndOfSession m = *(EndOfSession*)message;
            break;
        }

        case 0x21: // AddOrderLong
        {
            AddOrderLong m = *(AddOrderLong *)message;
            Order::Side side = m.SideIndicator == 'B' ? Order::Side::Buy : Order::Side::Sell;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.add_order(m.OrderId, m.Symbol, m.Price, m.Quantity, side);
            break;
        }
        case 0x22: // AddOrderShort
        {
            AddOrderShort m = *(AddOrderShort *)message;
            Order::Side side = m.SideIndicator == 'B' ? Order::Side::Buy : Order::Side::Sell;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.add_order(m.OrderId, m.Symbol, m.Price, m.Quantity, side);
            break;
        }

        case 0x23: // OrderExecuted
        {
            OrderExecuted m = *(OrderExecuted*)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.execute_order(m.OrderId, m.ExecutedQuantity);
            break;
        }

        case 0x25: // ReduceSizeLong
        {
            ReduceSizeLong m = *(ReduceSizeLong *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.reduce_order(m.OrderId, m.CancelledQuantity);
            break;
        }
        case 0x26: // ReduceSizeShort
        {
            ReduceSizeShort m = *(ReduceSizeShort *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.reduce_order(m.OrderId, m.CancelledQuantity);
            break;
        }

        case 0x27: // ModifyOrderLong
        {
            ModifyOrderLong m = *(ModifyOrderLong *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.modify_order(m.OrderId, m.Price, m.Quantity);

            break;
        }
        case 0x28: // ModifyOrderShort
        {
            ModifyOrderShort m = *(ModifyOrderShort *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.modify_order(m.OrderId, m.Price, m.Quantity);
            break;
        }

        case 0x29: // DeleteOrder
        {
            DeleteOrder m = *(DeleteOrder*)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.cancel_order(m.OrderId);
            break;
        }
        default:
        {
            // Handle unknown message types
            throw std::invalid_argument("Error: unrecognized message type " + std::to_string(msg_type));
        }
    }
}

void CBOEPcapParser::process_packet(const u_char *packet) noexcept
{
    int offset = 42;

    SequencedUnitHeader suHeader = *(SequencedUnitHeader *)(packet + offset);

    // Skip PITCH packets for Unit other than 1, unsequenced PITCH packets, and
    // those with zero messages (heartbeats)
    //(Time sequences will be reset to 1 each day when feed startup)
    if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
    {
        return;
    }

    uint64_t pktSeqNum = suHeader.HdrSequence;
	uint64_t msgSeqNum = suHeader.HdrSequence;

    // First message in packet
    offset += sizeof(SequencedUnitHeader);
    MessageHeader msgHeader = *(MessageHeader *)(packet + offset);
    process_message(pktSeqNum, msgSeqNum, packet + offset + 2, msgHeader.MsgType);

    // All remaining messages in packet
    for (int j = 0; j < suHeader.HdrCount - 1; j++)
    {
        ++msgSeqNum;
        offset += msgHeader.MsgLen;
        msgHeader = *(MessageHeader *)(packet + offset);
        process_message(pktSeqNum, msgSeqNum, packet + offset + 2, msgHeader.MsgType);
    }
}

void CBOEPcapParser::start()
{
    auto& config = Config::getInstance();

    StopWatch sw;
    if (config.time())
    {
        std::string name = "Day " + std::to_string(m_id) + " Time";
        sw.set_name(name);
        sw.Start();
    }

    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to store error messages
    pcap_t* pcap;                   // PCAP handle
    struct pcap_pkthdr header; // Header for packet metadata
    const u_char* packet;      // Pointer to the packet data

    // Attempt to open the provided PCAP file in offline mode
    pcap = pcap_open_offline(m_pcapFilename.c_str(), errbuf);
    if (pcap == nullptr) 
    {
        throw std::runtime_error("Error: Unable to open the file " + m_pcapFilename);
    }
    std::size_t counter = 0;

    // Process each packet in the PCAP file
    while ((packet = pcap_next(pcap, &header)) != nullptr) 
    {
        ++counter;
        process_packet(packet);

        if (config.showOB())
        {
            auto args = config.orderbook();
            std::string time = args[1] + " " + args[2];

            m_dataExporter.orderbook_printer(args[0], time);
        }
    }
    
    // Close the PCAP file
    pcap_close(pcap);

    sw.Stop();
    sw.display_time();
}

void CBOEPcapParser::messages_summary()
{
    auto& config = Config::getInstance();

    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to store error messages
    pcap_t* pcap;                   // PCAP handle
    struct pcap_pkthdr header; // Header for packet metadata
    const u_char* packet;      // Pointer to the packet data

    // Attempt to open the provided PCAP file in offline mode
    pcap = pcap_open_offline(m_pcapFilename.c_str(), errbuf);
    if (pcap == nullptr) 
    {
        throw std::runtime_error("Error: Unable to open the file " + m_pcapFilename);
    }
    // Process each packet in the PCAP file
    while ((packet = pcap_next(pcap, &header)) != nullptr) 
    {
        if (config.gaps())
            gap_helper(packet);
        if (config.msgSummary())
            messages_summary_helper(packet);
    }
    // Close the PCAP file
    pcap_close(pcap);


    if (config.gaps())
    {
        if (!m_messageInfo.packet_gaps.empty())
        {
            std::cout << "Packet gap(s) detected:\n";
            for (const auto& [expected, actual] : m_messageInfo.packet_gaps)
            {
                std::cout << "Expected packet sequence number: " << expected
                << " | Actual: " << actual << std::endl;
            }
        }
        else
        {
            std::cout << "No packet gap detected!\n" << std::endl;
        }
    }

    if (config.msgSummary())
    {
        std::cout << "Message Counts by Date and Type:" << std::endl;
        for (const auto& dateEntry : m_messageInfo.dailyMessageCounts)
        {
            if (dateEntry.first.empty())
                continue;

            std::string date = dateEntry.first;
            date.insert(4, "-");
            date.insert(7, "-");

            std::cout << "Date: " << date << std::endl;
            for (const auto& typeEntry : m_messageInfo.messageTypeInfo)
            {
                auto it = dateEntry.second.find(typeEntry.first);
                if (it != dateEntry.second.end())
                {
                    std::cout << std::format("  Type: {:<28} (0x{:02X}) - Count: {:>9}\n",
                                            typeEntry.second,
                                            static_cast<int>(typeEntry.first),
                                            it->second);
                }
                else
                {
                    std::cout << std::format("  Type: {:<28} (0x{:02X}) - Count: {:>9}\n",
                                            typeEntry.second,
                                            static_cast<int>(typeEntry.first),
                                            0);
                }
            }
        }
        std::cout << std::endl;
    }
    m_messageInfo = MessageInfo{}; // Reset the message counter
}

void CBOEPcapParser::gap_helper(const u_char *packet) noexcept
{
    int offset = 42;
    SequencedUnitHeader suHeader = *(SequencedUnitHeader *)(packet + offset);

    if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
    {
        return;
    }

    // Gap detection
    if (m_messageInfo.gNextExpectedPacketSeqNum)
    {
        if (suHeader.HdrSequence != m_messageInfo.gNextExpectedPacketSeqNum && suHeader.HdrSequence != 1)
        {
            unsigned int hdrSeq = suHeader.HdrSequence;
            m_messageInfo.packet_gaps.push_back({m_messageInfo.gNextExpectedPacketSeqNum, hdrSeq});
        }
    }
    m_messageInfo.gNextExpectedPacketSeqNum = suHeader.HdrSequence + suHeader.HdrCount;
}

void CBOEPcapParser::messages_summary_helper(const u_char *packet) noexcept
{
    int offset = 42;
    SequencedUnitHeader suHeader = *(SequencedUnitHeader *)(packet + offset);

    if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
    {
        return;
    }

    // First message in packet
    offset += sizeof(SequencedUnitHeader);
    MessageHeader msgHeader = *(MessageHeader *)(packet + offset);
    m_messageInfo.totalMessages++;
    m_messageInfo.messageCounts[msgHeader.MsgType]++;
    
    // Ensure the date entry exists in the map
    if (!m_messageInfo.dailyMessageCounts.contains(m_messageInfo.currentTradeDate)) 
    {
        m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate] = std::unordered_map<uint8_t, int>();
    }
    m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate][msgHeader.MsgType]++;
    if (msgHeader.MsgType == 0xB1) // TimeReference
    {
        TimeReference m = *(TimeReference*)(packet + offset + 2);
        m_messageInfo.currentTradeDate = std::to_string(m.TradeDate);
    }

    // All remaining messages in packet
    for (int j = 0; j < suHeader.HdrCount - 1; j++)
    {
        offset += msgHeader.MsgLen;
        msgHeader = *(MessageHeader *)(packet + offset);
        m_messageInfo.totalMessages++;
        m_messageInfo.messageCounts[msgHeader.MsgType]++;
        
        // Ensure the date entry exists in the map
        if (!m_messageInfo.dailyMessageCounts.contains(m_messageInfo.currentTradeDate)) 
        {
            m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate] = std::unordered_map<uint8_t, int>();
        }
        m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate][msgHeader.MsgType]++;

        if (msgHeader.MsgType == 0xB1) // TimeReference
        {
            TimeReference m = *(TimeReference*)(packet + offset + 2);
            m_messageInfo.currentTradeDate = std::to_string(m.TradeDate);
        }
    }
}

// ------------------ PCAP Slicer ------------------

PcapSlicer::PcapSlicer(const std::string& filename) 
    : m_pcapFilename(filename)
{}

std::string PcapSlicer::slice_pcap(const std::string& begin_time, const std::string& end_time, const std::string& output_filename)
{
    // Display the full filepath of the output 
    std::filesystem::path p = std::filesystem::absolute(output_filename);

    // Regex to check that the begin_time and end_time have good format
    const std::regex time_pattern(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$)");

    if (!std::regex_match(begin_time, time_pattern) || !std::regex_match(end_time, time_pattern)) 
    {
        throw std::invalid_argument("Invalid format for the start or end time: Expected format (ISO 8601) is 'YYYY-MM-DDTHH:MM:SS'");
    }

    std::stringstream command;
    command << "editcap -A " << begin_time << " -B " << end_time << " " << m_pcapFilename << " " << output_filename;
    
    std::cout << "\nSlicing pcap file. Executing command: " << command.str() << std::endl;
    
    int result = std::system(command.str().c_str());
    
    if (result == 0)
    {
        std::cout << "Slicing executed successfully. File was placed at: " << p << "\n\n";
        return p;
    }
    else
        throw std::invalid_argument("Failed to execute editcap command");   
}

void PcapSlicer::daily_slice()
{
    // Open the input PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(m_pcapFilename.c_str(), errbuf);
    if (pcap == nullptr)
    {
        throw std::runtime_error("Error: Unable to open the file " + m_pcapFilename);
    }

    const u_char* packet;
    struct pcap_pkthdr* header;

    // Prepare for slicing
    std::size_t dayCount = 1;
    pcap_t* pcap_out = nullptr;
    pcap_dumper_t* pcap_dumper = nullptr;

    auto open_new_output_file = [&]() 
    {
        if (pcap_out != nullptr) 
        {
            pcap_dump_flush(pcap_dumper);  // Flush any buffered data
            pcap_dump_close(pcap_dumper);  // Close previous dumper
            pcap_close(pcap_out);          // Close previous handle
        }

        pcap_out = pcap_open_dead(pcap_datalink(pcap), 65535); // Use same link-layer header type
        std::string output_file = "../day" + std::to_string(dayCount++) + ".pcap";
        pcap_dumper = pcap_dump_open(pcap_out, output_file.c_str());
        if (pcap_dumper == nullptr) 
        {
            throw std::runtime_error("Error opening output file: " + std::string(pcap_geterr(pcap_out)));
        }

        // Set a larger buffer size for the output file
        FILE* dump_file = pcap_dump_file(pcap_dumper);
        setvbuf(dump_file, NULL, _IOFBF, 4 * 1024 * 1024); // 4 MB buffer
    };

    // Open the first output file
    open_new_output_file();

    int ret;
    while ((ret = pcap_next_ex(pcap, &header, &packet)) >= 0)
    {
        if (ret == 0) 
        {
            // Timeout elapsed (should not happen in offline mode)
            continue;
        }

        // Ensure we have enough data
        int offset = 42; // Adjust if necessary
        if (header->caplen < offset + sizeof(SequencedUnitHeader)) 
        {
            continue; // Not enough data
        }

        SequencedUnitHeader suHeader;
        std::memcpy(&suHeader, packet + offset, sizeof(SequencedUnitHeader));

        // Filter packets based on header fields
        if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
        {
            continue;
        }

        // Check for new day or sequence reset
        if (m_gNextExpectedPacketSeqNum != suHeader.HdrSequence)
        {
            // Write current file and open a new one
            open_new_output_file();
        }

        // Update the next expected sequence number
        m_gNextExpectedPacketSeqNum = suHeader.HdrSequence + suHeader.HdrCount;

        // Write the current packet to the output file
        pcap_dump(reinterpret_cast<u_char*>(pcap_dumper), header, packet);
    }

    if (ret == -1) 
    {
        std::cerr << "Error reading the packet: " << pcap_geterr(pcap) << std::endl;
    }

    // Clean up and close files
    if (pcap_out != nullptr) {
        pcap_dump_flush(pcap_dumper);  // Ensure all data is written
        pcap_dump_close(pcap_dumper);
        pcap_close(pcap_out);
    }
    pcap_close(pcap);
}

