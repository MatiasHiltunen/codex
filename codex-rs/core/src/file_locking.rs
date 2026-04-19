use std::fs::TryLockError;
use std::io::Error;
use std::io::ErrorKind;

pub(crate) fn is_unsupported_lock_error(error: &Error) -> bool {
    error.kind() == ErrorKind::Unsupported
}

pub(crate) fn is_unsupported_try_lock_error(error: &TryLockError) -> bool {
    match error {
        TryLockError::Error(error) => is_unsupported_lock_error(error),
        TryLockError::WouldBlock => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_unsupported_lock_error;
    use super::is_unsupported_try_lock_error;
    use pretty_assertions::assert_eq;
    use std::fs::TryLockError;
    use std::io::Error;
    use std::io::ErrorKind;

    #[test]
    fn identifies_unsupported_lock_errors() {
        let unsupported = Error::from(ErrorKind::Unsupported);
        let other = Error::other("boom");

        assert!(is_unsupported_lock_error(&unsupported));
        assert!(!is_unsupported_lock_error(&other));
    }

    #[test]
    fn identifies_unsupported_try_lock_errors() {
        let unsupported = TryLockError::Error(Error::from(ErrorKind::Unsupported));
        let other = TryLockError::Error(Error::other("boom"));

        assert!(is_unsupported_try_lock_error(&unsupported));
        assert!(!is_unsupported_try_lock_error(&other));
        assert_eq!(
            is_unsupported_try_lock_error(&TryLockError::WouldBlock),
            false
        );
    }
}
