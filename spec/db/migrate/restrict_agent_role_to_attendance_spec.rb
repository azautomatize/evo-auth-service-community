# frozen_string_literal: true

require 'rails_helper'
require Rails.root.join('db/migrate/20261004120003_restrict_agent_role_to_attendance.rb')

RSpec.describe RestrictAgentRoleToAttendance do
  let(:migration) { described_class.new }

  before { load Rails.root.join('db/seeds/rbac.rb') }

  def keys(role)
    role.reload.role_permissions_actions.pluck(:permission_key)
  end

  it 'revokes shared-resource writes and bulk import/export from the agent and grants profile keys' do
    agent = Role.find_by!(key: 'agent')
    described_class::REVOKED_PERMISSIONS.each { |pk| agent.role_permissions_actions.find_or_create_by!(permission_key: pk) }
    agent.role_permissions_actions.where(permission_key: described_class::GRANTED_PERMISSIONS).delete_all

    migration.up

    expect(keys(agent)).not_to include(*described_class::REVOKED_PERMISSIONS)
    expect(keys(agent)).to include(*described_class::GRANTED_PERMISSIONS)
    expect(keys(agent)).to include('conversations.update', 'labels.read', 'macros.execute', 'pipeline_items.update')
  end

  it 'leaves the admin roles untouched' do
    owner = Role.find_by!(key: 'account_owner')
    before_keys = keys(owner)

    migration.up

    expect(keys(owner)).to match_array(before_keys)
  end

  it 'is idempotent' do
    migration.up
    expect { migration.up }.not_to raise_error
  end
end
