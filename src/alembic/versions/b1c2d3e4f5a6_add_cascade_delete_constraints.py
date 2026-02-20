"""add cascade delete constraints

Revision ID: b1c2d3e4f5a6
Revises: 436b0d3452b6
Create Date: 2026-02-20 14:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, Sequence[str], None] = '436b0d3452b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add ON DELETE CASCADE to foreign key constraints."""
    # file_tasks.file_id -> files.id
    with op.batch_alter_table('file_tasks', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_file_tasks_file_id_files'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_file_tasks_file_id_files'),
            'files', ['file_id'], ['id'],
            ondelete='CASCADE',
        )

    # userblock_entries.username -> users.username
    with op.batch_alter_table('userblock_entries', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_userblock_entries_username_users'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_userblock_entries_username_users'),
            'users', ['username'], ['username'],
            ondelete='CASCADE',
        )

    # userblock_sub_entries.parent_id -> userblock_entries.block_id
    with op.batch_alter_table('userblock_sub_entries', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_userblock_sub_entries_parent_id_userblock_entries'),
            type_='foreignkey',
        )
        batch_op.create_foreign_key(
            op.f('fk_userblock_sub_entries_parent_id_userblock_entries'),
            'userblock_entries', ['parent_id'], ['block_id'],
            ondelete='CASCADE',
        )

    # user_permissions.username -> users.username
    with op.batch_alter_table('user_permissions', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_user_permissions_username_users'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_user_permissions_username_users'),
            'users', ['username'], ['username'],
            ondelete='CASCADE',
        )

    # user_memberships.username -> users.username
    # user_memberships.group_name -> user_groups.group_name
    with op.batch_alter_table('user_memberships', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_user_memberships_username_users'), type_='foreignkey'
        )
        batch_op.drop_constraint(
            op.f('fk_user_memberships_group_name_user_groups'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_user_memberships_username_users'),
            'users', ['username'], ['username'],
            ondelete='CASCADE',
        )
        batch_op.create_foreign_key(
            op.f('fk_user_memberships_group_name_user_groups'),
            'user_groups', ['group_name'], ['group_name'],
            ondelete='CASCADE',
        )

    # group_permissions.group_name -> user_groups.group_name
    with op.batch_alter_table('group_permissions', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_group_permissions_group_name_user_groups'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_group_permissions_group_name_user_groups'),
            'user_groups', ['group_name'], ['group_name'],
            ondelete='CASCADE',
        )

    # keyrings.username -> users.username
    with op.batch_alter_table('keyrings', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_keyrings_username_users'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_keyrings_username_users'),
            'users', ['username'], ['username'],
            ondelete='CASCADE',
        )

    # folders.parent_id -> folders.id
    with op.batch_alter_table('folders', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_folders_parent_id_folders'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_folders_parent_id_folders'),
            'folders', ['parent_id'], ['id'],
            ondelete='CASCADE',
        )

    # documents.folder_id -> folders.id
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_documents_folder_id_folders'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_documents_folder_id_folders'),
            'folders', ['folder_id'], ['id'],
            ondelete='CASCADE',
        )


def downgrade() -> None:
    """Remove ON DELETE CASCADE from foreign key constraints."""
    # documents.folder_id -> folders.id
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_documents_folder_id_folders'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_documents_folder_id_folders'),
            'folders', ['folder_id'], ['id'],
        )

    # folders.parent_id -> folders.id
    with op.batch_alter_table('folders', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_folders_parent_id_folders'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_folders_parent_id_folders'),
            'folders', ['parent_id'], ['id'],
        )

    # keyrings.username -> users.username
    with op.batch_alter_table('keyrings', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_keyrings_username_users'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_keyrings_username_users'),
            'users', ['username'], ['username'],
        )

    # group_permissions.group_name -> user_groups.group_name
    with op.batch_alter_table('group_permissions', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_group_permissions_group_name_user_groups'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_group_permissions_group_name_user_groups'),
            'user_groups', ['group_name'], ['group_name'],
        )

    # user_memberships.username -> users.username
    # user_memberships.group_name -> user_groups.group_name
    with op.batch_alter_table('user_memberships', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_user_memberships_username_users'), type_='foreignkey'
        )
        batch_op.drop_constraint(
            op.f('fk_user_memberships_group_name_user_groups'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_user_memberships_username_users'),
            'users', ['username'], ['username'],
        )
        batch_op.create_foreign_key(
            op.f('fk_user_memberships_group_name_user_groups'),
            'user_groups', ['group_name'], ['group_name'],
        )

    # user_permissions.username -> users.username
    with op.batch_alter_table('user_permissions', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_user_permissions_username_users'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_user_permissions_username_users'),
            'users', ['username'], ['username'],
        )

    # userblock_sub_entries.parent_id -> userblock_entries.block_id
    with op.batch_alter_table('userblock_sub_entries', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_userblock_sub_entries_parent_id_userblock_entries'),
            type_='foreignkey',
        )
        batch_op.create_foreign_key(
            op.f('fk_userblock_sub_entries_parent_id_userblock_entries'),
            'userblock_entries', ['parent_id'], ['block_id'],
        )

    # userblock_entries.username -> users.username
    with op.batch_alter_table('userblock_entries', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_userblock_entries_username_users'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_userblock_entries_username_users'),
            'users', ['username'], ['username'],
        )

    # file_tasks.file_id -> files.id
    with op.batch_alter_table('file_tasks', schema=None) as batch_op:
        batch_op.drop_constraint(
            op.f('fk_file_tasks_file_id_files'), type_='foreignkey'
        )
        batch_op.create_foreign_key(
            op.f('fk_file_tasks_file_id_files'),
            'files', ['file_id'], ['id'],
        )
