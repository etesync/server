import typing as t

from redis import asyncio as aioredis

from etebase_server.django import app_settings


class RedisWrapper:
    redis: aioredis.Redis

    def __init__(self, redis_uri: t.Optional[str]):
        self.redis_uri = redis_uri

    async def setup(self):
        if self.redis_uri is not None:
            self.redis = await aioredis.from_url(self.redis_uri)

    async def close(self):
        if hasattr(self, "redis"):
            await self.redis.close()

    @property
    def is_active(self):
        return self.redis_uri is not None


redisw = RedisWrapper(app_settings.REDIS_URI)
