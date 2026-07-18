from typing import Optional, List

class HTTPSRecordProbe:
    @staticmethod
    async def discover(client, host: str):
        from ...dns.models import DNSRecordType
        from ...dns.errors import DNSError

        try:
            records = await client.resolve(host, DNSRecordType.HTTPS)

        except DNSError:
            return None

        service = [record for record in records if record.data.priority != 0]

        if not service:
            return None

        return min(service, key=lambda record: record.data.priority).data

    @staticmethod
    async def supports_h3(client, host: str) -> bool:
        record = await HTTPSRecordProbe.discover(client, host)

        return record is not None and "h3" in record.alpn

    @staticmethod
    async def ech(client, host: str) -> Optional[bytes]:
        record = await HTTPSRecordProbe.discover(client, host)

        return record.ech if record is not None else None
