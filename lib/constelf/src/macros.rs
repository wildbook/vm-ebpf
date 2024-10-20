#[macro_export]
macro_rules! tryres {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Err(e),
        }
    };
}

#[macro_export]
macro_rules! tryopt {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return None,
        }
    };
}

#[macro_export]
macro_rules! ensure {
    (None, $expression:expr) => {
        if !$expression {
            return None;
        }
    };
    ($err:expr, $expression:expr) => {
        if !$expression {
            return Err($err);
        }
    };
}

#[macro_export]
macro_rules! ensure_matches {
    ($err:expr, $expression:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        if !matches!($expression, $pattern $(if $guard)?) {
            return Err($err);
        }
    };
}

pub use {ensure, ensure_matches, tryopt, tryres};
