from pydantic_settings import BaseSettings


class Configs(BaseSettings):
    DOMAIN: str
    PORT: int
    ROOT_PATH: str
    API_TOKEN: str
    DEBUG: bool = False
    LISTEN_ADDRESS: str = "127.0.0.1"
    LISTEN_PORT: int = 28261

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'


CONFIGS = Configs()  # type: ignore
