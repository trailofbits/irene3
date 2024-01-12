#pragma once

#include <variant>

namespace irene3::patchlang
{
    class RegisterLocation;
    class MemoryLocation;
    class IndirectMemoryLocation;

    using Location = std::variant< RegisterLocation, MemoryLocation, IndirectMemoryLocation >;
} // namespace irene3::patchlang