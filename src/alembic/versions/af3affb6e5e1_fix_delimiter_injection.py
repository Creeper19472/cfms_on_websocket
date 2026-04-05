"""fix delimiter injection

Revision ID: af3affb6e5e1
Revises: 50df72915860
Create Date: 2026-04-06 01:07:21.638660

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'af3affb6e5e1'
down_revision: Union[str, Sequence[str], None] = '50df72915860'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("DELETE FROM login_security")
    with op.batch_alter_table('login_security', schema=None) as batch_op:
        batch_op.add_column(sa.Column('username', sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column('ip_address', sa.String(length=45), nullable=False))
        batch_op.create_index(batch_op.f('ix_login_security_ip_address'), ['ip_address'], unique=False)
        
        batch_op.drop_constraint('pk_login_security', type_='primary')
        batch_op.drop_column('identifier')
        batch_op.create_primary_key('pk_login_security', ['username', 'ip_address'])

def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM login_security")
    with op.batch_alter_table('login_security', schema=None) as batch_op:
        batch_op.add_column(sa.Column('identifier', sa.VARCHAR(length=128), nullable=False))
        
        batch_op.drop_constraint('pk_login_security', type_='primary')
        
        batch_op.drop_index(batch_op.f('ix_login_security_ip_address'))
        batch_op.drop_column('ip_address')
        batch_op.drop_column('username')
        
        batch_op.create_primary_key('pk_login_security', ['identifier'])
