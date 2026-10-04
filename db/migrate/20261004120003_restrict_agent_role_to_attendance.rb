# frozen_string_literal: true

# Padrao do papel `agent`: atende conversas e edita o proprio perfil, sem gerenciar
# recursos compartilhados da conta. Etiquetas, respostas rapidas e etapas de funil
# alimentam automacoes e jornadas; importar/exportar contatos e importar historico
# de conversas sao operacoes de massa. Tudo isso passa a ser do administrador.
#
# O agente continua USANDO esses recursos na conversa: aplicar etiqueta e
# conversations.update, resposta rapida e macro sao `.read`/`macros.execute`,
# mover card no funil e pipeline_items.update.
#
# As permissoes de perfil sao garantidas (o atendente precisa trocar nome, foto,
# senha e notificacoes). Como o papel agora e editavel na tela de Perfis, o
# administrador pode reverter qualquer item depois; esta migracao roda uma vez.
class RestrictAgentRoleToAttendance < ActiveRecord::Migration[7.1]
  ROLE_KEY = 'agent'

  REVOKED_PERMISSIONS = %w[
    labels.create labels.update labels.delete labels.write
    canned_responses.create canned_responses.update canned_responses.delete canned_responses.write
    pipeline_stages.create pipeline_stages.update pipeline_stages.delete pipeline_stages.write
    contacts.import contacts.export
    conversations.import
  ].freeze

  GRANTED_PERMISSIONS = %w[
    profiles.read profiles.update profiles.update_avatar profiles.update_password profiles.manage_notifications
  ].freeze

  def up
    return unless ActiveRecord::Base.connection.table_exists?(:roles)
    return unless ActiveRecord::Base.connection.table_exists?(:role_permissions_actions)

    role = Role.find_by(key: ROLE_KEY)
    return unless role

    role.role_permissions_actions.where(permission_key: REVOKED_PERMISSIONS).delete_all
    GRANTED_PERMISSIONS.each do |key|
      next if role.role_permissions_actions.exists?(permission_key: key)

      role.role_permissions_actions.create!(permission_key: key)
    end
  end

  # Sem regrant no rollback: devolver escrita ao agente seria escalada de privilegio.
  def down; end
end
