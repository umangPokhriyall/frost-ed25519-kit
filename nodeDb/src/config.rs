use dotenv::from_filename;
use std::env;

pub struct Config {
    pub db_url: String,
}

impl Default for Config {
    fn default() -> Self {
        // explicitly load nodeDb/.env
        from_filename("nodeDb/.env").ok();

        let db_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| panic!("Please provide the database_url env variable"));
        Self { db_url }
    }
}
