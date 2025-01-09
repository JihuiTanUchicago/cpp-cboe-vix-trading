#pragma once

#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <boost/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>

#include "Order.hpp"
#include "cfepitch.h"
#include "Symbol.hpp"

class OrderBookManager;

class DataExporter
{
public:
    using PacketInfos = std::tuple<std::time_t, uint32_t, uint32_t, uint64_t, uint64_t>;
    using SymbolToReadableBimap = boost::bimap<boost::bimaps::unordered_set_of<Symbol, std::hash<Symbol>>, boost::bimaps::unordered_set_of<std::string>>;
public:
    explicit DataExporter(std::size_t id) noexcept;
    DataExporter(const DataExporter& bbot) = delete;
    DataExporter& operator =(const DataExporter& bbot) = delete;
    DataExporter(DataExporter&& other) = delete;
    DataExporter& operator=(DataExporter&& other) = delete;
    ~DataExporter() noexcept;

    void set_obm(OrderBookManager* obm);
    void set_date(std::time_t date);
    void set_time_ref(uint32_t time) noexcept;
    void set_time_offset(uint32_t time) noexcept;
    void set_packet_infos(uint64_t pktSqNum, uint64_t msgSqNum) noexcept;
    std::string get_human_readable_symbol(const Symbol& symbol) const noexcept;
    void store_BBO_records(char msgType, const Symbol& symbol, Order::Price bidPrice, uint32_t bidQuantity,
                   Order::Price askPrice, uint32_t askQuantity, uint8_t tradingStatus) noexcept;
    void write_BBO_to_binary(char msgType, const std::string& symbol, Order::Price bidPrice, uint32_t bidQuantity,
                                       Order::Price askPrice, uint32_t askQuantity, uint8_t tradingStatus);
    void symbol_tostring(const Symbol& symbol, FuturesInstrumentDefinition m, const unsigned char *message) noexcept;
    void orderbook_printer(const std::string& symbol, const std::string& time);

private:
    void time_stamp_tostring() noexcept;
    void flush_binary_buffer();
    void flush_csv_buffer();

private:
    OrderBookManager* m_obm;
    std::ostringstream m_bboBuffer;
    std::ofstream m_binaryOutfile; // Binary file stream
    SymbolToReadableBimap m_symbolToReadableMap;  // Symbol to readable <-> readable to symbol bimap
    std::string m_filename;
    // The following are cached data used to improve performance
    char m_Time[30];
    char m_date[12];
    uint32_t m_timeRef;
    uint32_t m_timeOffset;
    uint64_t m_pktSqNum;
    uint64_t m_msgSqNum;
};