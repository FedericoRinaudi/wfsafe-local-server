use regex::Regex;
#[macro_export]
macro_rules! impl_from_data {
    ($type:ty, $validate:expr) => {
        use rocket::data::ToByteUnit as _;
        use rocket::tokio::io::AsyncReadExt as _;

        #[rocket::async_trait]
        impl<'r> rocket::data::FromData<'r> for $type {
            type Error = String;

            async fn from_data(
                _req: &'r rocket::Request<'_>,
                data: rocket::Data<'r>,
            ) -> rocket::data::Outcome<'r, Self> {
                let mut buf = String::new();
                if let Err(e) = data.open(512.kibibytes()).read_to_string(&mut buf).await {
                    return rocket::data::Outcome::Error((
                        rocket::http::Status::InternalServerError,
                        e.to_string(),
                    ));
                }

                match rocket::serde::json::serde_json::from_str::<$type>(&buf) {
                    Ok(value) => {
                        if let Err(e) = $validate(&value) {
                            return rocket::data::Outcome::Error((
                                rocket::http::Status::BadRequest,
                                e,
                            ));
                        }
                        rocket::data::Outcome::Success(value)
                    }
                    Err(e) => rocket::data::Outcome::Error((
                        rocket::http::Status::UnprocessableEntity,
                        e.to_string(),
                    )),
                }
            }
        }
    };
}

#[macro_export]
macro_rules! parse_ip_to_u32 {
    ($ip_str:expr) => {
        $ip_str.parse::<Ipv4Addr>().expect("Invalid IP").into()
    };
}

pub fn validate_ip(ip: &str) -> Result<(), String> {
    let ipv4_regex =
        Regex::new(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-4]|2[0-4]\d|1\d\d|[1-9]\d?)$")
            .unwrap();
    if ipv4_regex.is_match(ip) {
        Ok(())
    } else {
        Err("Invalid IP address".to_string())
    }
}
