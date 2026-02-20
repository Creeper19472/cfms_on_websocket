"""argon2id feature

Revision ID: 9c6ab2902b6e
Revises: cbd5f06cfb68
Create Date: 2026-02-20 17:36:18.762203

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c6ab2902b6e'
down_revision: Union[str, Sequence[str], None] = 'cbd5f06cfb68'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Make the 'salt' column nullable so that:
    - Existing users retain their SHA-256 salt and can still log in.
    - On first successful login after this migration, the server automatically
      re-hashes the password with argon2id and sets salt to NULL.
    - New users created after this migration will always have salt = NULL
      and an argon2id pass_hash.
    """
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('salt',
                              existing_type=sa.TEXT(),
                              nullable=True)


def downgrade() -> None:
    """Downgrade schema.

    Restore the salt column as NOT NULL.
    Any rows whose salt was set to NULL during the argon2id upgrade will
    receive an empty string so that the NOT NULL constraint is satisfied;
    those rows will need their passwords reset to restore full SHA-256
    compatibility.
    """
    connection = op.get_bind()
    connection.execute(sa.text("UPDATE users SET salt = '' WHERE salt IS NULL"))
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('salt',
                              existing_type=sa.TEXT(),
                              nullable=False)
