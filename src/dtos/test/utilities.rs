#[cfg(test)]
mod ipv4_tests {
    use crate::dtos::utilities::validate_ip;

    #[test]
    fn valid_ip_address() {
        assert!(validate_ip("192.168.1.1").is_ok());
    }

    #[test]
    fn valid_ip_address_with_octet_zero() {
        assert!(validate_ip("192.0.1.1").is_ok());
    }

    #[test]
    fn invalid_ip_address_with_last_octet_zero() {
        assert!(validate_ip("192.168.1.0").is_err());
    }

    #[test]
    fn invalid_broadcast_ip_address() {
        assert!(validate_ip("192.168.1.255").is_err());
    }

    #[test]
    fn invalid_ip_address_with_out_of_range_octet() {
        assert!(validate_ip("256.168.1.1").is_err());
    }

    #[test]
    fn invalid_ip_address_with_out_of_range_last_octet() {
        assert!(validate_ip("255.168.1.256").is_err());
    }

    #[test]
    fn invalid_ip_address_with_non_numeric_characters() {
        assert!(validate_ip("192.168.1.a").is_err());
    }

    #[test]
    fn invalid_ip_address_with_too_few_octets() {
        assert!(validate_ip("192.168.1").is_err());
    }

    #[test]
    fn invalid_ip_address_with_too_many_octets() {
        assert!(validate_ip("192.168.1.1.1").is_err());
    }

    #[test]
    fn invalid_ip_address_with_out_point() {
        assert!(validate_ip("192.168.11").is_err());
    }
}
