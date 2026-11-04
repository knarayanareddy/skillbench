"""SQLAlchemy Core metadata mirroring database/migrations (drift-tested)."""

from src.models.foundation import metadata as foundation_metadata
from src.models.skb import metadata as skb_metadata

metadata = foundation_metadata
for _table in skb_metadata.tables.values():
    _table.to_metadata(metadata)
