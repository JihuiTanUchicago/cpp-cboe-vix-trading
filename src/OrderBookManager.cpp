#include <unordered_map>
#include <format>
#include <stdexcept>
#include <ranges>
#include <fstream>

#include "OrderBookManager.hpp"
#include "Order.hpp"

OrderBookManager::OrderBookManager(OrderStore* os, DataExporter* dataExporter) noexcept
    : m_orderbooks{}, m_orderstore(os), m_dataExporter{dataExporter}
{
}

void OrderBookManager::add_orderbook(const Symbol& ob, uint16_t contractSize, uint64_t tickSize) noexcept
{
    if (m_orderbooks.contains(ob))
        return;
    m_orderbooks.try_emplace(ob, ob, contractSize, tickSize, m_orderstore, m_dataExporter); // Construct orderbook in-place in the map
}

void OrderBookManager::remove_orderbook(const Symbol& ob)
{
    m_orderbooks.erase(ob);
}

void OrderBookManager::add_order(Order::ID id, const Symbol& symbol, Order::Price price, Order::Quantity quantity, Order::Side side)
{
    m_orderbooks.at(symbol).add_order(id, price, quantity, side);
}

void OrderBookManager::cancel_order(Order::ID order_id)
{
    m_orderbooks.at((*m_orderstore)[order_id].get_symbol()).cancel_order(order_id);
}

void OrderBookManager::modify_order(Order::ID order_id, Order::Price new_price, Order::Quantity new_qty)
{
    m_orderbooks.at((*m_orderstore)[order_id].get_symbol()).modify_order(order_id, new_price, new_qty);
}

void OrderBookManager::reduce_order(Order::ID order_id, Order::Quantity new_qty)
{
    m_orderbooks.at((*m_orderstore)[order_id].get_symbol()).reduce_order(order_id, new_qty);
}

void OrderBookManager::execute_order(Order::ID order_id, Order::Quantity executed_qty)
{
    m_orderbooks.at((*m_orderstore)[order_id].get_symbol()).execute_order(order_id, executed_qty);
}

void OrderBookManager::update_tradingStatus(const Symbol& symbol, OrderBook::TradingStatus tradingStatus)
{
    m_orderbooks.at(symbol).update_tradingStatus(tradingStatus);
}

bool OrderBookManager::contains(const Symbol& ob) const noexcept
{
    return m_orderbooks.contains(ob);
}

bool OrderBookManager::contains(Order::ID order_id) const noexcept
{
    return m_orderstore->contains(order_id);
}

const OrderBook& OrderBookManager::operator[](const Symbol& ob) const
{
    return m_orderbooks.at(ob);
}

const Order& OrderBookManager::find_order(Order::ID order_id) const
{
    return (*m_orderstore)[order_id];
}