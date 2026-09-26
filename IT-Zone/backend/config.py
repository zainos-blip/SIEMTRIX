from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    dmz_base_url: str = "https://entrap-underfed-collapse.ngrok-free.dev"
    dmz_api_user: str = "admin"
    dmz_api_pass: str = "password"
    jwt_secret: str = "supersecretkey"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    sqlite_db_path: str = "users.db"
    rate_limit_max: int = 10
    rate_limit_window: int = 60

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
