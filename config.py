from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Aegis AI Firewall"
    host: str = "127.0.0.1"
    port: int = 8000

    llm_provider: str = "mock"
    openai_api_key: str = ""
    anthropic_api_key: str = ""

    sentinel_model_path: str = "sentinel_model.joblib"
    sentinel_vectorizer_path: str = "vectorizer.joblib"

    redactor_model_path: str = "firewall/aegis_redactor"

    database_path: str = "aegis.db"


settings = Settings()
