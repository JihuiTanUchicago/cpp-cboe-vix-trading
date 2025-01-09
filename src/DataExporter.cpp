#include <string>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <stdexcept>

#include "DataExporter.hpp"
#include "OrderBookManager.hpp"
#include "cfepitch.h"

DataExporter::DataExporter(std::size_t id) noexcept
    : m_bboBuffer{}, m_binaryOutfile{}, m_symbolToReadableMap{}, m_filename{"../bbo" + std::to_string(id) + ".bin"}, 
    m_Time{}, m_date{}, m_timeRef{}, m_timeOffset{}, m_pktSqNum{}, m_msgSqNum{}
{
    //m_binaryOutfile.open(m_filename, std::ios::out | std::ios::binary);
}

DataExporter::~DataExporter()
{
    flush_csv_buffer();
    //flush_binary_buffer();

    if (m_binaryOutfile.is_open()) 
    {
        m_binaryOutfile.close();
        std::string fn = "../bbo" + std::string(m_date) + ".bin";
        //std::rename(m_filename.c_str(), fn.c_str());
    }
}

void DataExporter::set_obm(OrderBookManager* obm)
{
    m_obm = obm;
}

void DataExporter::set_date(std::time_t date)
{
    std::tm date_buffer = *std::gmtime(&date);
    std::snprintf(m_date, 12, "%04d-%02d-%02d", date_buffer.tm_year + 1900, date_buffer.tm_mon + 1, date_buffer.tm_mday);
}

void DataExporter::set_time_ref(uint32_t time) noexcept
{
    m_timeRef = time;
}

void DataExporter::set_time_offset(uint32_t timeOffset) noexcept
{
    m_timeOffset = timeOffset;
}

void DataExporter::set_packet_infos(uint64_t pktSqNum, uint64_t msgSqNum) noexcept
{
    m_pktSqNum = pktSqNum;
    m_msgSqNum = msgSqNum;
}

std::string DataExporter::get_human_readable_symbol(const Symbol& symbol) const noexcept
{
    return m_symbolToReadableMap.left.at(symbol);
}

void DataExporter::store_BBO_records(char msgType, const Symbol& symbol, Order::Price bidPrice, uint32_t bidQuantity,
                   Order::Price askPrice, uint32_t askQuantity, uint8_t tradingStatus) noexcept
{
    time_stamp_tostring();

    m_bboBuffer << m_Time << ','
                << m_pktSqNum << ','
                << m_msgSqNum << ','
                << msgType << ','
                << m_symbolToReadableMap.left.at(symbol) << ','
                << bidPrice * 10e-3 << ','
                << bidQuantity << ','
                << askPrice * 10e-3 << ','
                << askQuantity << ','
                << tradingStatus << '\n';
}


void DataExporter::write_BBO_to_binary(char msgType, const std::string& symbol, Order::Price bidPrice, uint32_t bidQuantity,
                                       Order::Price askPrice, uint32_t askQuantity, uint8_t tradingStatus)
{
    if (!m_binaryOutfile.is_open()) 
    {
        throw std::invalid_argument("Binary file is not open for writing.\n");
    }

    time_stamp_tostring();
    // Serialize data in binary format
    // Assuming m_date and m_Time are null-terminated strings
    m_binaryOutfile.write(reinterpret_cast<const char*>(m_Time), sizeof(m_Time));

    m_binaryOutfile.write(reinterpret_cast<const char*>(&m_timeRef), sizeof(m_timeRef));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&m_timeOffset), sizeof(m_timeOffset));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&m_pktSqNum), sizeof(m_pktSqNum));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&m_msgSqNum), sizeof(m_msgSqNum));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&msgType), sizeof(msgType));

    // Write symbol length and content
    uint32_t symbolLength = static_cast<uint32_t>(symbol.size());
    m_binaryOutfile.write(reinterpret_cast<const char*>(&symbolLength), sizeof(symbolLength));
    m_binaryOutfile.write(symbol.data(), symbolLength);

    // Write prices and quantities
    double bidPriceConverted = static_cast<double>(bidPrice) * 10e-3;
    double askPriceConverted = static_cast<double>(askPrice) * 10e-3;

    m_binaryOutfile.write(reinterpret_cast<const char*>(&bidPriceConverted), sizeof(bidPriceConverted));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&bidQuantity), sizeof(bidQuantity));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&askPriceConverted), sizeof(askPriceConverted));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&askQuantity), sizeof(askQuantity));
    m_binaryOutfile.write(reinterpret_cast<const char*>(&tradingStatus), sizeof(tradingStatus));
}

// Function to convert currentTradedate, currentTimeInSecs, and timeOffset to a timestamp string
void DataExporter::time_stamp_tostring() noexcept
{    
    // Calculate hours, minutes, and seconds from timeInSecs
    int hours = m_timeRef / 3600;
    int minutes = (m_timeRef % 3600) / 60;
    int seconds = m_timeRef % 60;

    // Format the timestamp directly
    std::snprintf(m_Time, 30, "%s %02d:%02d:%02d.%09u", m_date, hours, minutes, seconds, m_timeOffset);
}

void DataExporter::symbol_tostring(const Symbol& symbol, FuturesInstrumentDefinition m, const unsigned char *message) noexcept
{
    if (m.LegCount == 0) 
        {
            std::string report_symbol;
            for (uint8_t ch : m.ReportSymbol) 
            {
                char c = static_cast<char>(ch);
                if (isalnum(c)) 
                {
                    report_symbol += c;
                }
                else 
                {
                    break;
                }
            }

            int year_code = (m.ExpirationDate / 10000) % 10;
            int month = (m.ExpirationDate / 100) % 100;
            static constexpr const char* monthCodes = "FGHJKMNQUVXZ";
            char month_code;
            if (month >= 1 && month <= 12) 
            {
                month_code = monthCodes[month - 1];
            }
            else
            {
                month_code = '?';
            }
            std::string readable_code;
            readable_code.reserve(report_symbol.size() + 2);

            readable_code += report_symbol;
            readable_code += month_code;
            readable_code += static_cast<char>('0' + year_code);

            m_symbolToReadableMap.insert({symbol, readable_code});
        }
        else 
        { //spread instrument
            std::string readable_code;
            const uint8_t* baseAddress = (uint8_t*)message + m.LegOffset - 2;
            for (int i = 0; i < m.LegCount; ++i) 
            {
                int32_t leg_ratio = *(uint32_t*)(baseAddress + 10 * i);
                uint8_t leg_symbol_arr[6];
                memcpy(leg_symbol_arr, baseAddress + 4 + 10 * i, 6);
                Symbol leg_symbol(leg_symbol_arr);
                if (leg_ratio == 1) {
                    readable_code += '+';
                }
                else if (leg_ratio == -1) {
                    readable_code += '-';
                }
                else {
                    std::cerr << "an error occur (leg ratio error)";
                }
                readable_code += m_symbolToReadableMap.left.at(leg_symbol);
            }
            m_symbolToReadableMap.insert({symbol, readable_code});
        }
}

void DataExporter::flush_csv_buffer()
{
    std::string output_filename = "../bbo-" + std::string(m_date) + ".csv";
    std::ofstream outfile;
    outfile.open(output_filename, std::ios::out);

    if (!outfile.is_open()) 
    {
        throw std::ios_base::failure("Failed to open file: " + output_filename);
    }

    outfile << "Time,PktSeqNum,MsgSeqNum,MsgType,Symbol,BidPrice,BidQuantity,AskPrice,AskQuantity,TradingStatus\n";
    outfile << m_bboBuffer.str();
    m_bboBuffer.str("");  // Clear the buffer
    m_bboBuffer.clear();  // Reset error flags

    if (outfile.is_open()) 
    {
        outfile.close();
    }
}

void DataExporter::flush_binary_buffer()
{
    if (m_binaryOutfile.is_open()) 
    {
        m_binaryOutfile.flush();
    }
}

void DataExporter::orderbook_printer(const std::string& symbol, const std::string& time)
{
    time_stamp_tostring();
    if (time == std::string(m_Time))
    {
        m_obm->operator[](m_symbolToReadableMap.right.at(symbol)).print_book();
    }
}