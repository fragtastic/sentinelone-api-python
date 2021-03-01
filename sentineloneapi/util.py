import datetime

datetime_format: str = '%Y-%m-%dT%H:%M:%S.%fZ'


def parse_datetime(stamp: str) -> datetime.datetime:
    return datetime.datetime.strptime(stamp, datetime_format)
