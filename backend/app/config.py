"""Application configuration via pydantic-settings."""

from __future__ import annotations

import os

from pydantic import AliasChoices, Field, model_validator
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

    # Ingest limits & performance tuning
    ingest_chunk_rows: int = 50_000
    ingest_workers: int = 8
    ingest_chunk_size_mb: int = 64
    ingest_batch_rows: int = 50_000
    ingest_compression: str = "zstd"
    max_memory_gb: int = 6

    # DuckDB performance tuning
    duckdb_memory_limit_gb: int = 4
    duckdb_threads: int = 8
    duckdb_temp_directory: str = ""

    # LLM settings (supports both GEMINI_API_KEY and LLM_GEMINI_API_KEY)
    llm_gemini_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("LLM_GEMINI_API_KEY", "GEMINI_API_KEY", "llm_gemini_api_key", "gemini_api_key"),
    )
    llm_model: str = Field(
        default="",
        validation_alias=AliasChoices("LLM_MODEL", "GEMINI_MODEL", "llm_model", "gemini_model"),
    )
    llm_call_budget: int = 20
    llm_timeout_seconds: float = 30.0
    llm_thinking_effort: str = "low"  # "low" | "medium" for Gemini 3.x thinking models
    llm_pregen_delay_seconds: float = 1.0

    @model_validator(mode="after")
    def populate_llm_defaults(self) -> Settings:
        if not self.llm_gemini_api_key:
            self.llm_gemini_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("LLM_GEMINI_API_KEY") or ""
        if not self.llm_model:
            self.llm_model = os.getenv("LLM_MODEL") or os.getenv("GEMINI_MODEL") or ""
            if not self.llm_model and self.llm_gemini_api_key:
                self.llm_model = "gemini-3.5-flash-lite"
        return self

    # Neo4j (optional)
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # Reach engine
    reach_engine: str = "networkx"

    # Incident linking
    incident_link_window_seconds: int = 1800
    incident_link_hub_threshold: int = 50
    incident_exclude_entities: list[str] = [
        "FGT60FTK00000000",
        "10.10.99.1",
        "127.0.0.1",
        "8.8.8.8",
        "0.0.0.0",
        "unknown",
    ]

    def __repr__(self) -> str:
        attrs = {
            k: ("***" if "key" in k.lower() and v else v)
            for k, v in self.__dict__.items()
            if not k.startswith("_")
        }
        return f"Settings({attrs})"

    def __str__(self) -> str:
        return repr(self)


settings = Settings()
