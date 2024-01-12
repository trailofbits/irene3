#include <irene3/PatchLang/Types.h>

namespace irene3::patchlang
{
    const Type& ArrayType::GetType() const { return *elem_type; }
} // namespace irene3::patchlang