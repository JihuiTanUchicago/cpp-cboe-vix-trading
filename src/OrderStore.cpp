#include "OrderStore.hpp"

Order* OrderStore::add_order(Order::ID id, const Symbol& symbol, Order::Price price, Order::Quantity quantity, Order::Side side)
{
    // Construct order in-place by forwarding key and arguments for Order constructor
    m_orders.try_emplace(id, id, symbol, price, quantity, side);

    return &m_orders.at(id);
}

Order& OrderStore::operator[] (Order::ID order_id)
{
    return m_orders.at(order_id);
}

void OrderStore::erase(Order::ID order_id)
{
    m_orders.erase(order_id);
}

const Order& OrderStore::operator[] (Order::ID order_id) const
{
    return m_orders.at(order_id);
}

bool OrderStore::contains(Order::ID order_id) const noexcept
{
    return m_orders.contains(order_id);
}