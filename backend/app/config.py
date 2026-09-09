from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SAT-SA"
    environment: str = "development"
    database_url: str = "postgresql://postgres:postgres@localhost:5432/sat_sa"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()