"""use-argon2id-drop-salt

Revision ID: a1b2c3d4e5f6
Revises: cbd5f06cfb68
Create Date: 2026-02-20 09:25:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'cbd5f06cfb68'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the salt column from users table (salt is now embedded in the argon2id hash)."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('salt')


def downgrade() -> None:
    """Re-add the salt column (existing pass_hash values will be incompatible with legacy SHA-256 auth)."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('salt', sa.Text(), nullable=False, server_default=''))
