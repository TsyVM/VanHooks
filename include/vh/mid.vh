#pragma once

/**
 * vh/mid.vh
 * MidContext and MidCallback re-exported into the vh:: namespace.
 * Mid-function hooks receive a MidContext* holding a snapshot of all
 * general-purpose registers and flags at the hook site.
 */

#include <vanhooks/vanhooks.vh>

namespace vh {

using vanhooks::MidContext;
using vanhooks::MidCallback;

} // namespace vh
