#pragma once

#include <unordered_map>
#include <memory>

#include "OrderBook.hpp"
#include "OrderStore.hpp"
#include "DataExporter.hpp"
#include "Symbol.hpp"

class OrderBookManager
{
public:
    using OrderBooks = std::unordered_map<Symbol, OrderBook>;

public:
    explicit OrderBookManager(OrderStore* os, DataExporter* dataExporter) noexcept;
    OrderBookManager(const OrderBookManager& ob) = delete;
    OrderBookManager& operator = (const OrderBookManager& ob) = delete;
    OrderBookManager(OrderBookManager&& ob) = delete;
    OrderBookManager& operator = (OrderBookManager&& ob) = delete;
    ~OrderBookManager() noexcept = default;

    void add_orderbook(const Symbol& ob, uint16_t contractSize, uint64_t tickSize) noexcept;
    void remove_orderbook(const Symbol& ob);
    void add_order(Order::ID id, const Symbol& symbol, Order::Price price, Order::Quantity quantity, Order::Side side);
    void cancel_order(Order::ID order_id);
    void modify_order(Order::ID order_id, Order::Price new_price, Order::Quantity new_qty);
    void reduce_order(Order::ID order_id, Order::Quantity new_qty);
    void execute_order(Order::ID order_id, Order::Quantity executed_qty);
    void update_tradingStatus(const Symbol& symbol, OrderBook::TradingStatus tradingStatus);

    bool contains(const Symbol& ob) const noexcept;
    bool contains(Order::ID order_id) const noexcept;
    const OrderBook& operator[](const Symbol& ob) const;
    const Order& find_order(Order::ID order_id) const;

private:
    OrderBooks m_orderbooks;
    OrderStore* m_orderstore; // Pointer to the order store located in CBOEParser
    DataExporter* m_dataExporter;
};