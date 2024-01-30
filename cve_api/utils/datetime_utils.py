from datetime import datetime, timedelta


def get_current_time() -> str:
    return datetime.now()


def get_older_date(date: datetime, days_back: int) -> datetime:
    date_n_days_before = (date - timedelta(days=days_back)).replace(hour=0, minute=0, second=0, microsecond=0)
    return date_n_days_before


def convert_date_to_iso_format(date: datetime) -> str:
    return date.isoformat()


def get_dates(days_back):
    end_date = get_current_time()
    start_date = get_older_date(end_date, days_back)
    return start_date, end_date
