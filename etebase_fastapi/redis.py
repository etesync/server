import typing as t
import aioredis

from django_etebase import app_settings


class RedisWrapper:
    redis: aioredis.Redis

    def __init__(self, redis_uri: t.Optional[str]):
        self.redis_uri = redis_uri

    async def setup(self):
        if self.redis_uri is not None:
            self.redis = await aioredis.create_redis_pool(self.redis_uri)

    async def close(self):
        if hasattr(self, "redis"):
            self.redis.close()
            await self.redis.wait_closed()

    @property
    def is_active(self):
        return self.redis_uri is not None


redisw = RedisWrapper(app_settings.REDIS_URI)
