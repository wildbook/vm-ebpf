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

/// `for $i in $range $body` in a const context, where `for` isn't allowed. `$i` takes each value of the
/// [`Range`](std::ops::Range) `$range` in turn; `continue` and `break` work as in `for`.
macro_rules! const_for {
    ($i:ident in $range:expr => $body:block) => {{
        let std::ops::Range { start, end } = $range;
        let mut next = start;
        while next < end {
            let $i = next;
            next += 1;
            $body
        }
    }};
}
pub(crate) use const_for;
pub(crate) use ensure;
pub(crate) use ensure_matches;
pub(crate) use tryopt;
pub(crate) use tryres;
