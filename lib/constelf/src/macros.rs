macro_rules! tryres {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Err(e),
        }
    };
}

macro_rules! tryopt {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return None,
        }
    };
}

macro_rules! ensure {
    ($err:expr, $expression:expr) => {
        if !$expression {
            return Err($err);
        }
    };
}

macro_rules! ensure_matches {
    ($err:expr, $expression:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        if !matches!($expression, $pattern $(if $guard)?) {
            return Err($err);
        }
    };
}

/// `for $pat in $iter $body` in a const context, where `for` isn't allowed. `$iter` is a
/// [`Range`](std::ops::Range), whose values `$pat` takes in turn, or an array or slice, whose elements `$pat` takes by
/// value, or by reference behind a leading `&`. `continue` and `break` work as in `for`.
macro_rules! const_for {
    // `$iter` is the tokens before `=>`, a range if a `..` stands among them
    (@split $pat:tt [$($start:tt)*] .. $end:expr => $body:block) => {{
        let std::ops::Range { start, end } = ($($start)*)..$end;
        let mut next = start;
        while next < end {
            let $pat = next;
            next += 1;
            $body
        }
    }};
    (@split $pat:tt [& $($items:tt)*] => $body:block) => {
        $crate::const_for!(@each $pat [&] ($($items)*) $body)
    };
    (@split $pat:tt [$($items:tt)*] => $body:block) => {
        $crate::const_for!(@each $pat [] ($($items)*) $body)
    };
    (@split $pat:tt [$($done:tt)*] $token:tt $($rest:tt)*) => {
        $crate::const_for!(@split $pat [$($done)* $token] $($rest)*)
    };
    (@each $pat:tt [$($borrow:tt)?] ($items:expr) $body:block) => {{
        let items: &[_] = &$items;
        let mut next = 0;
        while next < items.len() {
            let $pat = $($borrow)? items[next];
            next += 1;
            $body
        }
    }};
    ($pat:pat in $($rest:tt)*) => {
        $crate::const_for!(@split $pat [] $($rest)*)
    };
}
pub(crate) use const_for;
pub(crate) use ensure;
pub(crate) use ensure_matches;
pub(crate) use tryopt;
pub(crate) use tryres;
