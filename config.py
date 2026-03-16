from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Aegis AI Firewall"
    host: str = "127.0.0.1"
    port: int = 8000

    LLM_PROVIDER: str = "openai"
    LLM_MODEL: str = "gpt-4o-mini"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    FPE_KEY: str = ""
    FPE_TWEAK: str = ""

    sentinel_model_path: str = "sentinel_model.joblib"
    sentinel_b_model_path: str = "sentinel_b_model.joblib"
    sentinel_vectorizer_path: str = "vectorizer.joblib"

    redactor_model_path: str = "firewall/aegis_redactor"
    ner_model_path: str = "redactor_ner_model.joblib"

    database_path: str = "banking.db"
    weil_key_path: str = "private_key.wc"

    @property
    def llm_provider(self) -> str:
        return self.LLM_PROVIDER

    @property
    def llm_model(self) -> str:
        return self.LLM_MODEL

    @property
    def openai_api_key(self) -> str:
        return self.OPENAI_API_KEY

    @property
    def anthropic_api_key(self) -> str:
        return self.ANTHROPIC_API_KEY

    @property
    def fpe_key(self) -> str:
        return self.FPE_KEY

    @property
    def fpe_tweak(self) -> str:
        return self.FPE_TWEAK


settings = Settings()
