from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Aegis AI Firewall"
    host: str = "127.0.0.1"
    port: int = 8000

    llm_provider: str = "mock"
    llm_model: str = "gpt-4o-mini"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    fpe_key: str = ""
    fpe_tweak: str = ""

    sentinel_model_path: str = "sentinel_model.joblib"
    sentinel_b_model_path: str = "sentinel_b_model.joblib"
    sentinel_vectorizer_path: str = "vectorizer.joblib"

    redactor_model_path: str = "firewall/aegis_redactor"
    ner_model_path: str = "redactor_ner_model.joblib"

    database_path: str = "banking.db"
    weilchain_db_path: str = "weilchain.db"
    weil_private_key: str = ""
    weil_applet_address: str = ""
    weil_bridge_path: str = "applet/bridge.js"


settings = Settings()
