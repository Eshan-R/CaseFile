"""Application configuration via pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"

    # DuckDB path (relative to repo root or absolute)
    duck_path: str = "./data/casefile.duckdb"
    parquet_dir: str = "./data/parquet"
    manifest_timezone: str = "Asia/Kolkata"

    # Ingest limits
    ingest_chunk_rows: int = 50_000
    max_memory_gb: int = 6

    # LLM (optional)
    llm_provider: str = "openai"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: int = 60

    # Neo4j (optional)
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # Reach engine
    reach_engine: str = "networkx"


settings = Settings()

