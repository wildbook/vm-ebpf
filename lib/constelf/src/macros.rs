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
pub(crate) use ensure;
pub(crate) use ensure_matches;
pub(crate) use tryopt;
pub(crate) use tryres;
