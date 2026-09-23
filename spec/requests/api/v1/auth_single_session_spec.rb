# frozen_string_literal: true

require 'rails_helper'

# CRM-664. One session per user is the posture: each sign-in revokes the
# tokens the user still holds. Nothing here changes that — what it pins is that
# the posture is enforced on the FIRST request made with a displaced token, and
# that the sign-in says how many sessions it displaced.
#
# Before the fix, `validate_bearer_token` (the cache-miss path) did not check
# `revoked?`, so the displaced token was answered 200 once and re-cached. The
# session only really died on the second request — which is exactly the
# "integrations knock each other out, sometimes" report.
RSpec.describe 'POST /api/v1/auth/login — single session (CRM-664)', type: :request do
  let(:password) { 'Test123!@' }

  let(:user) do
    User.create!(
      name: 'Session User',
      email: "single-session-#{SecureRandom.hex(4)}@example.com",
      password: password,
      password_confirmation: password,
      confirmed_at: Time.current
    )
  end

  def login
    post '/api/v1/auth/login', params: { email: user.email, password: password }, as: :json
    expect(response).to have_http_status(:ok)
    JSON.parse(response.body)['data']
  end

  # /auth/me is the endpoint the README hands to integrations; unlike
  # /profile it is not behind an RBAC permission, so it isolates the token
  # check from role resolution.
  def me_with(token)
    get '/api/v1/auth/me', headers: { 'Authorization' => "Bearer #{token}" }
  end

  before { Rails.cache.clear }

  it 'reports how many sessions the sign-in displaced' do
    first = login
    expect(first['revoked_sessions']).to eq(0)

    second = login
    expect(second['revoked_sessions']).to eq(1)
  end

  it 'refuses the displaced token on its very first request, not the second' do
    first = login
    first_token = first.dig('token', 'access_token')

    # The displaced token is cached as valid by this call.
    me_with(first_token)
    expect(response).to have_http_status(:ok)

    login # displaces it

    me_with(first_token)
    expect(response).to have_http_status(:unauthorized)
    expect(JSON.parse(response.body).dig('error', 'message')).to eq('Token has been revoked')
  end

  it 'keeps the newest session working' do
    login
    newest = login.dig('token', 'access_token')

    me_with(newest)
    expect(response).to have_http_status(:ok)
  end

  # The whole point of the posture: a server integration must not authenticate
  # by logging in. An API access token is a different table and a different
  # credential, and signing in does not touch it.
  it 'does not revoke an API access token when the user signs in' do
    api_token = AccessToken.create!(owner: user, name: 'integration', scopes: 'read write')

    login
    login

    get '/api/v1/auth/me', headers: { 'Api-Access-Token' => api_token.token }
    expect(response).to have_http_status(:ok)
  end

  # Finishing MFA goes through the same `render_successful_login`, so it carries
  # the same sweep and the same count. Deduced from reading once; exercised here,
  # because "same method, therefore same behaviour" is the kind of assumption
  # that hides a nil.
  describe 'the MFA path' do
    let(:mfa_user) do
      User.create!(
        name: 'MFA User',
        email: "single-session-mfa-#{SecureRandom.hex(4)}@example.com",
        password: password,
        password_confirmation: password,
        confirmed_at: Time.current,
        otp_required_for_login: true,
        mfa_method: :totp,
        mfa_confirmed_at: Time.current
      )
    end

    def temp_token_for(user)
      JWT.encode(
        { user_id: user.id, email: user.email, exp: 10.minutes.from_now.to_i },
        Rails.application.secret_key_base
      )
    end

    def finish_mfa(user)
      allow_any_instance_of(User).to receive(:validate_otp).and_return(true)
      post '/api/v1/mfa/verify',
           params: { email: user.email, code: '000000', temp_token: temp_token_for(user) },
           as: :json
      expect(response).to have_http_status(:ok)
      JSON.parse(response.body)['data']
    end

    it 'reports the displaced sessions after finishing MFA, like a plain login' do
      first = finish_mfa(mfa_user)
      expect(first['revoked_sessions']).to eq(0)

      second = finish_mfa(mfa_user)
      expect(second['revoked_sessions']).to eq(1)
    end

    it 'revokes the previous token on the first request, like a plain login' do
      first_token = finish_mfa(mfa_user).dig('token', 'access_token')

      get '/api/v1/auth/me', headers: { 'Authorization' => "Bearer #{first_token}" }
      expect(response).to have_http_status(:ok)

      finish_mfa(mfa_user)

      get '/api/v1/auth/me', headers: { 'Authorization' => "Bearer #{first_token}" }
      expect(response).to have_http_status(:unauthorized)
      expect(JSON.parse(response.body).dig('error', 'message')).to eq('Token has been revoked')
    end
  end
end
