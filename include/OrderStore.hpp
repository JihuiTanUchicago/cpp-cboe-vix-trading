#pragma once

#include <unordered_map>

#include "Order.hpp"
#include "Symbol.hpp"
class OrderStore
{
public:
    OrderStore() = default;
    OrderStore(const OrderStore& ob) = delete;
    OrderStore& operator=(const OrderStore& ob) = delete;
    OrderStore(OrderStore&& ob) = default;
    OrderStore& operator=(OrderStore&& ob) = default;
    ~OrderStore() noexcept = default;

    [[nodiscard]] Order* add_order(Order::ID id, const Symbol& symbol, Order::Price price, Order::Quantity quantity, Order::Side side);
    void erase(Order::ID order_id);
    Order& operator[] (Order::ID order_id);
    const Order& operator[] (Order::ID order_id) const;
    bool contains(Order::ID order_id) const noexcept;

private:
    std::unordered_map<Order::ID, Order> m_orders;
};