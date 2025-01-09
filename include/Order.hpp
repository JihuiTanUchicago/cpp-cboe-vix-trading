#pragma once

#include <cstdint>

#include "Symbol.hpp"

class Order
{
public:
    using Price = int64_t;
    using ID = uint64_t;
    using Quantity = uint16_t;
    enum class Side
    {
        Buy,
        Sell
    };

public:
    // Constructors
    explicit Order(ID id, const Symbol& symbol, Price price, Quantity quantity, Side side) noexcept;
    Order(const Order& order) = default;
    Order& operator=(const Order& order) = default;
    Order(Order&& order) noexcept = default;
    Order& operator=(Order&& order) noexcept = default;
    virtual ~Order() noexcept = default;

    ID get_id() const noexcept;
    const Symbol& get_symbol() const noexcept;
    Quantity get_initial_quantity() const noexcept;
    Quantity get_remaining_quantity() const noexcept;
    Quantity get_tradable_quantity() const noexcept;
    Side get_side() const noexcept;
    Price get_price() const noexcept;
    bool is_filled() const noexcept;
    void print_info() const;
    void fill(Quantity quantity);

private:
    Symbol m_symbol;
    ID m_id;
    Price m_price;
    Quantity m_initialQty;
    Quantity m_remainingQty;
    Quantity m_tradableQty;
    Side m_side;
};
