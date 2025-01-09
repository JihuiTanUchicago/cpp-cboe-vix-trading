#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

struct MessageInfo
{
  std::vector<std::pair<uint32_t, uint32_t>> packet_gaps;
  uint32_t gNextExpectedPacketSeqNum;
  std::unordered_map<uint8_t, int> messageCounts; // Message counts by type
  std::unordered_map<std::string, std::unordered_map<uint8_t, int>> dailyMessageCounts;
   // Messages per day and type
  int totalMessages = 0; // Total messages processed
  std::map<uint8_t, std::string> messageTypeInfo =
    {
        {0x20, "Time"},
        {0x21, "AddOrderLong"},
        {0x22, "AddOrderShort"},
        {0x23, "OrderExecuted"},
        {0x25, "ReduceSizeLong"},
        {0x26, "ReduceSizeShort"},
        {0x27, "ModifyOrderLong"},
        {0x28, "ModifyOrderShort"},
        {0x29, "DeleteOrder"},
        {0x2A, "TradeLong"},
        {0x2B, "TradeShort"},
        {0x2C, "TradeBreak"},
        {0x2D, "EndOfSession"},
        {0x31, "TradingStatus"},
        {0x97, "UnitClear"},
        {0xB1, "TimeReference"},
        {0xB9, "Settlement"},
        {0xBA, "EndOfDaySummary"},
        {0xBB, "FuturesInstrumentDefinition"},
        {0xBC, "TransactionBegin"},
        {0xBD, "TransactionEnd"},
        {0xBE, "PriceLimits"},
        {0xD3, "OpenInterest"}
    }; // Map of message type to message name
  std::string currentTradeDate; // Current trade date
};