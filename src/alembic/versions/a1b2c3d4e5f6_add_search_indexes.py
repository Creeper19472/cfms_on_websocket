"""add search indexes on documents.title and folders.name

Revision ID: a1b2c3d4e5f6
Revises: ccd985e08120
Create Date: 2026-03-08 03:13:38.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'ccd985e08120'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_documents_title'), ['title'], unique=False)
    with op.batch_alter_table('folders', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_folders_name'), ['name'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('folders', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_folders_name'))
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_documents_title'))
