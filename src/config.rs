const DEFAULT_DATABASE_URL: &str = "postgres://ironclad:ironclad@localhost:5432/ironclad";

pub fn database_url() -> Result<String, std::env::VarError> {
    match std::env::var("DATABASE_URL") {
        Ok(s) => Ok(s),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_DATABASE_URL.to_string()),
        Err(e) => Err(e),
    }
}

pub fn ollama_base_url() -> String {
    std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string())
}

pub fn ollama_model() -> String {
    std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "mistral".to_string())
}
