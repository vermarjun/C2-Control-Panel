import os
import asyncio
from sliver import SliverClientConfig, SliverClient

CONFIG_PATH = os.path.join('./arjun.cfg')

async def main():
    ''' Async client connect example '''
    config = SliverClientConfig.parse_config_file(CONFIG_PATH)
    client = SliverClient(config)
    await client.connect()
    operators = await client.operators()
    sessions = await client.sessions()
    print('Sessions: %r' % sessions)
    print('Operators: %r' % operators)

if __name__ == '__main__':
    asyncio.run(main())