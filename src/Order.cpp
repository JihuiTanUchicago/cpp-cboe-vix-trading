#include <format>
#include <iostream>
#include <stdexcept>

#include "Order.hpp"

Order::Order(ID id, const Symbol& symbol, Price price, Quantity quantity, Side side) noexcept
    : m_symbol{symbol}, m_id{id}, m_price{price}, m_initialQty{quantity}, 
      m_remainingQty{quantity}, m_tradableQty{quantity}, m_side{side}
{}

Order::ID Order::get_id() const noexcept
{
    return m_id;
}

const Symbol& Order::get_symbol() const noexcept
{
    return m_symbol;
}

Order::Quantity Order::get_initial_quantity() const noexcept
{
    return m_initialQty;
}

Order::Quantity Order::get_remaining_quantity() const noexcept
{
    return m_remainingQty;
}

Order::Quantity Order::get_tradable_quantity() const noexcept
{
    return m_tradableQty;
}

Order::Side Order::get_side() const noexcept
{
    return m_side;
}

Order::Price Order::get_price() const noexcept
{
    return m_price;
}

bool Order::is_filled() const noexcept
{
    return m_remainingQty > 0 ? false : true;
}

void Order::fill(Quantity quantity)
{
    if (quantity > m_remainingQty)
        throw std::logic_error(std::format("Cannot fill order {} by an amount greater than its remaining quantity! (remaining quantity: {})", m_id, m_remainingQty));

    m_remainingQty -= quantity;
}

void Order::print_info() const
{
    std::string side;
    switch (m_side) 
    {
        case Side::Buy: 
            side = "Buy";
            break;
        case Side::Sell: 
            side = "Sell";
            break;
    }

    std::string type = "Limit Order";

    std::cout << std::format(
        "-- LimitOrder Information --\n"
        "{:<20} {}\n"  // Align left in 20 spaces
        "{:<20} {}\n"
        "{:<20} {}\n"
        "{:<20} {}\n"
        "{:<20} {}\n"
        "{:<20} {}\n"
        "{:<20} {}\n",
        "ID:", m_id, 
        "Symbol:", std::string(reinterpret_cast<const char*>(m_symbol.symbol)),
        "Type:", type,                                           
        "Side:", side,                      
        "Price:", m_price,                   
        "Initial Quantity:", m_initialQty,        
        "Remaining Quantity:", m_remainingQty) << std::endl;     
}