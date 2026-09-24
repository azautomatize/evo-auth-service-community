# frozen_string_literal: true

require 'rails_helper'

# Signing in revokes the user's other Bearer tokens. The displaced token must be
# refused on its first request, which takes the cache-miss validation path.
RSpec.describe 'POST /api/v1/auth/login — single session', type: :request do
  include ActiveSupport::Testing::TimeHelpers

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

  it 'does not count a session past its refresh lifetime as displaced' do
    login

    travel 31.days do
      expect(login['revoked_sessions']).to eq(0)
    end
  end

  # No cookie: the Authorization fallback an integration outside the SPA uses.
  it 'rotates the credential on refresh and keeps the caller signed in' do
    old_token = login.dig('token', 'access_token')
    cookies.delete('_evo_rt')

    post '/api/v1/auth/refresh', headers: { 'Authorization' => "Bearer #{old_token}" }
    expect(response).to have_http_status(:ok)
    new_token = JSON.parse(response.body).dig('data', 'access_token')

    me_with(new_token)
    expect(response).to have_http_status(:ok)

    me_with(old_token)
    expect(response).to have_http_status(:unauthorized)
  end

  it 'keeps the newest session working' do
    login
    newest = login.dig('token', 'access_token')

    me_with(newest)
    expect(response).to have_http_status(:ok)
  end

  it 'does not revoke an API access token when the user signs in' do
    api_token = AccessToken.create!(owner: user, name: 'integration', scopes: 'read write')

    login
    login

    get '/api/v1/auth/me', headers: { 'Api-Access-Token' => api_token.token }
    expect(response).to have_http_status(:ok)
  end

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
