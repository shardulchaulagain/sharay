"""Alembic migrations run with the application connection."""

from alembic import context
from sqlalchemy import create_engine

from aegis.models import Base


def migrate(connection):
    context.configure(connection=connection, target_metadata=Base.metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    context.configure(
        url=context.config.get_main_option("sqlalchemy.url"),
        target_metadata=Base.metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    connection = context.config.attributes.get("connection")
    if connection is not None:
        migrate(connection)
    else:
        with create_engine(context.config.get_main_option("sqlalchemy.url")).begin() as connection:
            migrate(connection)
