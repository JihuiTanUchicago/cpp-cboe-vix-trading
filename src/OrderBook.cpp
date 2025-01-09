#include <memory>
#include <format>
#include <ranges>
#include <chrono>

#include "cfepitch.h"
#include "Config.hpp"
#include "OrderBook.hpp"
#include "OrderStore.hpp"

OrderBook::OrderBook(const Symbol& symbol, uint16_t contractSize, uint64_t tickSize, OrderStore* orderstore, DataExporter* dataExporter)
    : m_asks{}, m_bids{}, m_symbol{symbol}, m_tickSize{tickSize}, m_orderstore{orderstore}, m_dataExporter{dataExporter},
      m_contractSize{contractSize}, m_tradingStatus{'S'}
{
}

std::pair<Order::Price, Order::Quantity> OrderBook::get_best_bid() const noexcept
{
    if (m_bids.empty())
    {
        return {0,0};
    }

    auto best_bid = m_bids.begin();

    return {best_bid->first, best_bid->second.first};
}

std::pair<Order::Price, Order::Quantity> OrderBook::get_best_ask() const noexcept
{
    if (m_asks.empty()) 
    {
        return {0,0};
    }

    auto best_ask = m_asks.begin();
    
    return {best_ask->first, best_ask->second.first};
}

Order::Price OrderBook::get_best_bid_price() const noexcept
{
    return m_bids.begin()->first;
}

Order::Price OrderBook::get_best_ask_price() const noexcept
{
    return m_asks.begin()->first;
}

OrderBook::BBO OrderBook::get_bbo() const noexcept
{
    const auto& [bidPx, bidQty] = get_best_bid();
    const auto& [askPx, askQty] = get_best_ask();

    return {bidPx, bidQty, askPx, askQty};
}

OrderBook::Bids OrderBook::get_bids() const noexcept
{
    return m_bids;
}

OrderBook::Asks OrderBook::get_asks() const noexcept
{
    return m_asks;
}

OrderBook::TradingStatus OrderBook::get_trading_status() const noexcept
{
    return m_tradingStatus;
}

bool OrderBook::bids_empty() const noexcept
{
    return m_bids.empty();
}

bool OrderBook::asks_empty() const noexcept
{
    return m_asks.empty();
}

void OrderBook::print_book() const
{
    std::cout << "\n=================================\n"
              << std::format("{} Orderbook", m_dataExporter->get_human_readable_symbol(m_symbol)) 
              << "\n=================================\n";
    std::cout << "\n--------------------- ASKS ---------------------\n\n";
    if (m_asks.empty())
    {
        std::cout << "-EMPTY-" << "\n";
    }
    else
    { 
        for (auto&& [price, orders] : std::views::reverse(m_asks)) 
        {
            std::cout << std::format("{:<10}", price);
            for (const auto& order : orders.second)
            {
                std::cout << std::format("[{}]", order->get_remaining_quantity());
            }
            std::cout << "\n";
        }
    }

    std::cout << "\n--------------------- BIDS ---------------------\n\n";
    if (m_bids.empty())
    {
        std::cout << "-EMPTY-\n";       
    }
    else
    {
        for (const auto& [price, orders] : m_bids) 
        {
            std::cout << std::format("{:<10}", price);
            for (const auto& order : orders.second)
            {
                std::cout << std::format("[{}]", order->get_remaining_quantity());
            }
            std::cout << "\n";
        }
    }

    std::cout << std::endl;
}

void OrderBook::add_order(Order::ID id, Order::Price price, Order::Quantity quantity, Order::Side side)
{
    if (m_orderstore->contains(id))
    {
        throw std::invalid_argument("You cannot add an order with the same id as one already in the book");
    }

    Order* order_ptr = m_orderstore->add_order(id, m_symbol, price, quantity, side);

    OrderBook::BBO currentBBO{get_bbo()};

    if (side == Order::Side::Buy)
    {        
        m_bids[price].first += quantity;
        m_bids[price].second.push_back(order_ptr);
    }

    else
    {
        m_asks[price].first += quantity;
        m_asks[price].second.push_back(order_ptr);
    }

    auto newBBO = get_bbo();

    if (currentBBO != newBBO) // Check if the BBO is in a valid state by checking the quantity
    {
        if (Config::getInstance().bbo())
        {
            const auto& [bidPx, bidQty, askPx, askQty] = newBBO;
            m_dataExporter->store_BBO_records('A', m_symbol,  
                    bidPx, bidQty, askPx, askQty, m_tradingStatus);
        }
    }
}

void OrderBook::cancel_order(Order::ID order_id)
{
    if (!m_orderstore->contains(order_id))
    {
        throw std::invalid_argument(std::format("The order with ID {} does not exist in the orderbook", order_id));
    }

    OrderBook::BBO currentBBO{get_bbo()};

    const Order& order = m_orderstore->operator[](order_id);  // same as (*m_orderstore)[order_id]
    auto price = order.get_price();

    if (order.get_side() == Order::Side::Buy)
    {
        if (m_bids[price].second.size() == 1)
        {
            m_bids.erase(price);
            m_orderstore->erase(order_id);
        }
        else
        {
            m_bids[price].first -= order.get_remaining_quantity();
            std::erase_if(m_bids[price].second, 
                [&order, &order_id](const auto& bid){ return bid->get_id() == order_id;});
        }
    }
    else
    {
        if (m_asks[price].second.size() == 1)
        {
            m_asks.erase(price);
            m_orderstore->erase(order_id);
        }
        else
        {
            m_asks[price].first -= order.get_remaining_quantity();
            std::erase_if(m_asks[price].second, 
                [&order, &order_id](const auto& ask){ return ask->get_id() == order_id;});
        }
    }

    auto newBBO = get_bbo();

    if (currentBBO != newBBO) // Check if the BBO is in a valid state
    {
        if (Config::getInstance().bbo())
        {
            const auto& [bidPx, bidQty, askPx, askQty] = newBBO;
            m_dataExporter->store_BBO_records('D', m_symbol, 
                    bidPx, bidQty, askPx, askQty, m_tradingStatus);
        }
    }

    m_orderstore->erase(order_id);
}

void OrderBook::modify_order(Order::ID order_id, Order::Price new_price, Order::Quantity new_qty)
{
    if (!m_orderstore->contains(order_id))
    {
        throw std::invalid_argument(std::format("The order with ID {} does not exist in the orderbook", order_id));
    }
    OrderBook::BBO currentBBO{get_bbo()};

    Order& old_order = m_orderstore->operator[](order_id);
    auto old_price = old_order.get_price();

    if (new_price == old_price && new_qty < old_order.get_remaining_quantity())
    {
        reduce_internal(order_id, old_order.get_remaining_quantity() - new_qty); 
    }
    else
    {
        Order::Side old_side = old_order.get_side();
        cancel_internal(order_id);
        add_internal(order_id, new_price, new_qty, old_side);
    }

    auto newBBO = get_bbo();

    if (currentBBO != newBBO) // Check if the BBO is in a valid state
    {
        if (Config::getInstance().bbo())
        {
            const auto& [bidPx, bidQty, askPx, askQty] = newBBO;
                m_dataExporter->store_BBO_records('M', m_symbol, 
                    bidPx, bidQty, askPx, askQty, m_tradingStatus);
        }
    }
}

void OrderBook::reduce_order(Order::ID order_id, Order::Quantity cxl_qty)
{
    if (!m_orderstore->contains(order_id))
    {
        throw std::invalid_argument(std::format("The order with ID {} does not exist in the orderbook", order_id));
    }

    OrderBook::BBO currentBBO{get_bbo()};

    Order& order = m_orderstore->operator[](order_id);
    auto price = order.get_price();

    try
    {
        if (order.get_side() == Order::Side::Buy)
            m_bids[price].first -= cxl_qty;
        else
            m_asks[price].first -= cxl_qty;
        order.fill(cxl_qty);
    } 
    catch (const std::logic_error& e)
    {
        throw std::logic_error(e.what());
    }

    auto newBBO = get_bbo();

    if (currentBBO != newBBO) // Check is the BBO is in a valid state
    {
        if (Config::getInstance().bbo())
        {
            const auto& [bidPx, bidQty, askPx, askQty] = newBBO;
            m_dataExporter->store_BBO_records('R', m_symbol, 
                    bidPx, bidQty, askPx, askQty, m_tradingStatus);
        }
    }
}


void OrderBook::execute_order(Order::ID order_id, Order::Quantity executed_qty)
{    
    if (!m_orderstore->contains(order_id))
    {
        throw std::invalid_argument(std::format("The order with ID {} does not exist in the orderbook", order_id));
    }

    OrderBook::BBO currentBBO{get_bbo()};

    Order& order = m_orderstore->operator[](order_id);
    auto price = order.get_price();

    if (order.get_remaining_quantity() == executed_qty) // complete fill
    {
        if (order.get_side() == Order::Side::Buy)
        {
            if (order_id != m_bids[price].second.front()->get_id())
            {
                // This is a data integrity error: order book state fatally wrong
                throw std::logic_error(std::format("Order id {} is not first in bid queue", order.get_id()));
            }
            if (m_bids[price].second.size() == 1)
            {
                m_bids.erase(price);
            } 
            else
            {
                m_bids[price].first -= executed_qty;
                m_bids[price].second.erase(m_bids[price].second.begin());
            }

        } 
        else
        {
            if (order_id != m_asks[price].second.front()->get_id())
            {
                // This is a data integrity error: order book state fatally wrong
                throw std::logic_error(std::format("Order id {} is not first in ask queue", order.get_id()));
            }
            if (m_asks[price].second.size() == 1)
            {
                m_asks.erase(price);
            } 
            else
            {
                m_asks[price].first -= executed_qty;
                m_asks[price].second.erase(m_asks[price].second.begin());
            }
        }
        // Remove order from orderstore
        m_orderstore->erase(order_id);
    }
    else // not a full fill
    {
        try
        {
            if (order.get_side() == Order::Side::Buy)
                m_bids[price].first -= executed_qty;
            else
                m_asks[price].first -= executed_qty;
            order.fill(executed_qty);
        } 
        catch (const std::logic_error& e)
        {
            throw std::logic_error(e.what());
        }
    }

    auto newBBO = get_bbo();

    if (currentBBO != newBBO) // Check if the BBO is in a valid state
    {
        if (Config::getInstance().bbo())
        {
            const auto& [bidPx, bidQty, askPx, askQty] = newBBO;
            m_dataExporter->store_BBO_records('E', m_symbol, 
                    bidPx, bidQty, askPx, askQty, m_tradingStatus);
        }
    }
}

bool OrderBook::contains(Order::ID order_id) const
{
    return m_orderstore->contains(order_id);
}

void OrderBook::update_tradingStatus(TradingStatus tradingStatus)
{
    m_tradingStatus = tradingStatus;
}

const Order& OrderBook::find_order(Order::ID order_id) const
{
    if (m_orderstore->contains(order_id))
        return m_orderstore->operator[](order_id);

    else 
        throw std::invalid_argument("Order {} not found" + order_id);
}

void OrderBook::add_internal(Order::ID id, Order::Price price, Order::Quantity quantity, Order::Side side) noexcept
{
    Order* order_ptr = m_orderstore->add_order(id, m_symbol, price, quantity, side);

    if (side == Order::Side::Buy)
    {
        m_bids[price].first += quantity;
        m_bids[price].second.push_back(order_ptr);
    }

    else
    {
        m_asks[price].first += quantity;
        m_asks[price].second.push_back(order_ptr);
    }
}

void OrderBook::cancel_internal(Order::ID order_id) noexcept
{
    const Order& order = m_orderstore->operator[](order_id);  
    auto price = order.get_price();
    if (order.get_side() == Order::Side::Buy)
    {
        if (m_bids[price].second.size() == 1)
        {
            m_bids.erase(price);
            m_orderstore->erase(order_id);
            return;
        }
        
        m_bids[price].first -= order.get_remaining_quantity();
        std::erase_if(m_bids[price].second, 
                [&order, &order_id](const auto& ask){ return ask->get_id() == order_id;});
    }
    else
    {
        if (m_asks[price].second.size() == 1)
        {
            m_asks.erase(price);
            m_orderstore->erase(order_id);
            return;
        }

        m_asks[price].first -= order.get_remaining_quantity();
        std::erase_if(m_asks[price].second, 
                [&order, &order_id](const auto& ask){ return ask->get_id() == order_id;});
    }

    m_orderstore->erase(order_id);
}

void OrderBook::reduce_internal(Order::ID order_id, Order::Quantity cxl_qty) noexcept
{
    Order& order = m_orderstore->operator[](order_id);

    if (order.get_side() == Order::Side::Buy)
        m_bids[order.get_price()].first -= cxl_qty;
    else
        m_asks[order.get_price()].first -= cxl_qty;
    order.fill(cxl_qty);
}