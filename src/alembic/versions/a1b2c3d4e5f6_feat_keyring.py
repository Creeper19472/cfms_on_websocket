"""feat-keyring

Revision ID: a1b2c3d4e5f6
Revises: 9c6ab2902b6e
Create Date: 2026-02-20 11:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '9c6ab2902b6e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'keyrings',
        sa.Column('key_id', sa.VARCHAR(64), nullable=False),
        sa.Column('username', sa.VARCHAR(255), nullable=False),
        sa.Column('key_content', sa.Text(), nullable=False),
        sa.Column('label', sa.VARCHAR(255), nullable=True),
        sa.Column('is_primary', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_time', sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(['username'], ['users.username'],
                                name=op.f('fk_keyrings_username_users')),
        sa.PrimaryKeyConstraint('key_id', name=op.f('pk_keyrings')),
    )
    op.create_index(op.f('ix_keyrings_username'), 'keyrings', ['username'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_keyrings_username'), table_name='keyrings')
    op.drop_table('keyrings')
