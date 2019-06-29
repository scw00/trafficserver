
#pragma once

#include <functional>

#define Defer(name, function) DeferInternal(name)((function))

class DeferInternal
{
public:
  using DeferFunction = std::function<void()>;
  DeferInternal(DeferFunction func) : _func(func) {}

  void
  cancel()
  {
    this->_func = nullptr;
  }

  ~DeferInternal()
  {
    if (this->_func) {
      this->_func();
    }
  }

private:
  DeferFunction _func = nullptr;
};
