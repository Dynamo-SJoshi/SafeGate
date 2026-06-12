import os
from redis import Redis

class RedisProgressStore:
    def __init__(self):
        self._redis = None

    @property
    def redis(self):
        if self._redis is None:
            self._redis = Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
        return self._redis

    def __setitem__(self, key: str, value: int):
        self.redis.set(f"progress:{key}", value, ex=3600)

    def __contains__(self, key: str) -> bool:
        return self.redis.exists(f"progress:{key}") > 0

    def __delitem__(self, key: str):
        self.redis.delete(f"progress:{key}")

    def get(self, key: str, default=None):
        val = self.redis.get(f"progress:{key}")
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

progress_store = RedisProgressStore()

