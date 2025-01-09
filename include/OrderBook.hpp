#pragma once

#include <iostream>
#include <map>
#include <vector>
#include <unordered_map>
#include <memory>
#include <queue>
#include <tuple>

#include "DataExporter.hpp"
#include "Order.hpp"
#include "OrderStore.hpp"
#include "cfepitch.h"
#include "Symbol.hpp"

class OrderBook
{
public:
    using FilledOrders = std::vector<Order::ID>;
    // Need to test between list/vector/deque for best performance
    // So far, std::vector seems to be slightly faster. Even though removing element from the middle/beggining of a vector is more expensive
    // than for a std::list/deque, it seems that cache locality overcompensate for that
    using Bids = std::map<Order::Price, std::pair<Order::Quantity, std::vector<Order*>>, std::greater<Order::Price>>; 
    using Asks = std::map<Order::Price, std::pair<Order::Quantity, std::vector<Order*>>, std::less<Order::Price>>;
    using TradingStatus = uint8_t;
    using BBO = std::tuple<Order::Price, int32_t, Order::Price, int32_t>; // use int32_t instead of Order::Quantity to account for unspecified state

public:
    explicit OrderBook(const Symbol& symbol, uint16_t contractSize, uint64_t tickSize, OrderStore* s_orderstore, DataExporter* s_dataExporter);
    OrderBook(const OrderBook& ob) = delete;
    OrderBook& operator=(const OrderBook& ob) = delete;
    OrderBook(OrderBook&& ob) = delete;
    OrderBook& operator=(OrderBook&& ob) = delete;
    ~OrderBook() noexcept = default;

    std::pair<Order::Price, Order::Quantity> get_best_bid() const noexcept;
    std::pair<Order::Price, Order::Quantity> get_best_ask() const noexcept;
    Order::Price get_best_bid_price() const noexcept;
    Order::Price get_best_ask_price() const noexcept;
    BBO get_bbo() const noexcept;
    Bids get_bids() const noexcept;
    Asks get_asks() const noexcept;
    TradingStatus get_trading_status() const noexcept;
    bool bids_empty() const noexcept;
    bool asks_empty() const noexcept;
    void print_book() const;
    bool contains(Order::ID order_id) const;
    const Order& find_order(Order::ID order_id) const;

    void add_order(Order::ID id, Order::Price price, Order::Quantity quantity, Order::Side side);
    void cancel_order(Order::ID order_id);
    void modify_order(Order::ID order_id, Order::Price new_price, Order::Quantity new_qty);
    void reduce_order(Order::ID order_id, Order::Quantity cxl_qty);
    void execute_order(Order::ID order_id, Order::Quantity executed_qty);
    void update_tradingStatus(TradingStatus tradingStatus);

private:
    // Those three functions are required to avoid double counting in BBO
    void add_internal(Order::ID id, Order::Price price, Order::Quantity quantity, Order::Side side) noexcept;
    void cancel_internal(Order::ID order_id) noexcept;
    void reduce_internal(Order::ID order_id, Order::Quantity cxl_qty) noexcept;

private:
    Asks m_asks; // Storage for ask limit orders
    Bids m_bids; // Storage for bid limit orders
    Symbol m_symbol; // Symbol of the order book
    uint64_t m_tickSize; // Minimum price increment (in 1/100 cents units)
    OrderStore* m_orderstore; // Pointer to the order store located in CBOEParser
    DataExporter* m_dataExporter; // Pointer to the data exporter located in CBOEParser
    uint16_t m_contractSize;
    TradingStatus m_tradingStatus; // Current trading status of the order book
};