"""fix time plan constraints

Revision ID: 5189ff3d44ec
Revises: 4b0c9a9b2bd9
Create Date: 2025-04-21 16:25:24.589827

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5189ff3d44ec'
down_revision = '4b0c9a9b2bd9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('time_plan_detail', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=10), nullable=True))
        batch_op.drop_column('is_completed')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('time_plan_detail', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_completed', sa.BOOLEAN(), nullable=True))
        batch_op.drop_column('status')

    # ### end Alembic commands ###
