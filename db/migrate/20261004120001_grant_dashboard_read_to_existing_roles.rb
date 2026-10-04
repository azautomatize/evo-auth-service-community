# frozen_string_literal: true

# `dashboard.read` deixou de ser permissao basica (User::BASIC_READ_PERMISSIONS)
# e virou recurso do catalogo, editavel por papel. Para nao esconder o Dashboard
# de quem ja o via, todo papel existente recebe a chave — exceto o `agent`, que
# passa a cair direto em Conversas (o admin pode marcar a permissao de volta).
# Instalacoes novas recebem a chave pelo db/seeds/rbac.rb (account_owner e
# super_admin herdam o catalogo inteiro).
class GrantDashboardReadToExistingRoles < ActiveRecord::Migration[7.1]
  PERMISSION_KEY = 'dashboard.read'
  EXCLUDED_ROLE_KEYS = %w[agent].freeze

  def up
    return unless ActiveRecord::Base.connection.table_exists?(:roles)
    return unless ActiveRecord::Base.connection.table_exists?(:role_permissions_actions)

    Role.where.not(key: EXCLUDED_ROLE_KEYS).find_each do |role|
      next if role.role_permissions_actions.exists?(permission_key: PERMISSION_KEY)

      role.role_permissions_actions.create!(permission_key: PERMISSION_KEY)
    end
  end

  def down
    return unless ActiveRecord::Base.connection.table_exists?(:role_permissions_actions)

    RolePermissionsAction.where(permission_key: PERMISSION_KEY).delete_all
  end
end
