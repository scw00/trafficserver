

#include <functional>
#include "Defer.h"
#include "catch.hpp"

TEST_CASE("test defer")
{
  SECTION("defer callback")
  {
    bool call = false;
    {
      Defer(defer_1, [&call]() { call = true; });
    }

    REQUIRE(call == true);
  }

  SECTION("defer cancel")
  {
    bool call = false;
    {
      Defer(defer_1, [&call]() { call = true; });
      defer_1.cancel();
    }

    REQUIRE(call == false);
  }
}
