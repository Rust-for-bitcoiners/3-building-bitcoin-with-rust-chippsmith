#![allow(unused)]

enum MResult<T, E> {
    Ok(T),
    Err(E),
}

impl<T, E> MResult<T, E> {
    fn ok(value: T) -> Self {
        MResult::Ok(value)
    }
    // Function to create an Err variant
    fn err(error: E) -> Self {
        MResult::Err(error)
    }

    // Method to check if it's an Ok variant
    fn is_ok(&self) -> bool {
        match self {
            MResult::Ok(_) => true,
            MResult::Err(_) => false,
        }
    }

    // Method to check if it's an Err variant
    fn is_err(&self) -> bool {
        match self {
            MResult::Ok(_) => false,
            MResult::Err(_) => true,
        }
    }

    // Method to unwrap the Ok value, panics if it's an Err
    fn unwrap(self) -> T {
        match self {
            MResult::Ok(value) => value,
            MResult::Err(_) => panic!("Error value"),
        }
    }

    // Method to unwrap the Err value, panics if it's an Ok
    fn unwrap_err(self) -> E {
        match self {
            MResult::Ok(_) => panic!("Ok Value"),
            MResult::Err(error) => error,
        }
    }
}

// Add unit tests below

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ok() {
        let a: MResult<i32, String> = MResult::Ok(45);
        assert!(a.is_ok());
        assert_eq!(a.unwrap(), 45)
    }

    #[test]
    fn test_is_err() {
        let a: MResult<i32, String> = MResult::Err("Error Message".to_string());
        assert!(a.is_err());
    }

    #[test]
    fn test_unwrap() {
        let a: MResult<i32, String> = MResult::Ok(45);
        assert_eq!(a.unwrap(), 45);
    }

    #[test]
    fn test_unwrap_err() {
        let a: MResult<i32, String> = MResult::Err("Error Message".to_string());
        assert_eq!(a.unwrap_err(), "Error Message");
    }
}
