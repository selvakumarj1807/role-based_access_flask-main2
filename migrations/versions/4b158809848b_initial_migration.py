"""Initial migration

Revision ID: 4b158809848b
Revises: 696f3a4a6ab0
Create Date: 2024-06-03 18:53:21.580583

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '4b158809848b'
down_revision = '696f3a4a6ab0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('role_permission')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password', sa.String(length=128), nullable=True))
        batch_op.drop_column('password_hash')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_hash', mysql.VARCHAR(length=128), nullable=True))
        batch_op.drop_column('password')

    op.create_table('role_permission',
    sa.Column('role_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False),
    sa.Column('permission_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False),
    sa.Column('id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['permission.id'], name='role_permission_ibfk_1'),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], name='role_permission_ibfk_2'),
    sa.PrimaryKeyConstraint('role_id', 'permission_id'),
    mysql_collate='utf8mb4_general_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    # ### end Alembic commands ###
