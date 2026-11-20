//! Loops and tables for const contexts.

/// `for $pat in $iter { $body }` in a const context, where `for` isn't allowed. `$iter` is a
/// [`Range`](std::ops::Range), whose values `$pat` takes in turn, or an array or slice, whose elements `$pat` takes by
/// value, or by reference behind a leading `&`. `$body` is a block or a single expression. `continue` and `break` work
/// as in `for`.
macro_rules! const_for {
    // `$iter` is the tokens before `=>`, a range if a `..` stands among them
    (@split $pat:tt [$($start:tt)*] .. $end:expr => $body:expr) => {{
        let std::ops::Range { start, end } = ($($start)*)..$end;
        let mut next = start;
        while next < end {
            let $pat = next;
            next += 1;
            $body;
        }
    }};
    (@split $pat:tt [& $($items:tt)*] => $body:expr) => {
        const_for!(@each $pat [&] ($($items)*) $body)
    };
    (@split $pat:tt [$($items:tt)*] => $body:expr) => {
        const_for!(@each $pat [] ($($items)*) $body)
    };
    (@split $pat:tt [$($done:tt)*] $token:tt $($rest:tt)*) => {
        const_for!(@split $pat [$($done)* $token] $($rest)*)
    };
    (@each $pat:tt [$($borrow:tt)?] ($items:expr) $body:expr) => {{
        let items: &[_] = &$items;
        let mut next = 0;
        while next < items.len() {
            let $pat = $($borrow)? items[next];
            next += 1;
            $body;
        }
    }};
    ($pat:pat in $($rest:tt)*) => {
        const_for!(@split $pat [] $($rest)*)
    };
}

/// A table with the value of `$value` for each opcode byte `$byte`.
macro_rules! byte_table {
    (|$byte:ident| $value:expr) => {{
        let mut table = [{
            let $byte = 0u8;
            $value
        }; 256];
        const_for!(i in 1..256 => {
            let $byte = i as u8;
            table[i] = $value;
        });
        table
    }};
}
