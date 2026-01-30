require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LinkedIn < OmniAuth::Strategies::OAuth2
      option :name, 'linkedin'

      option :client_options, {
        site: 'https://api.linkedin.com',
        authorize_url: 'https://www.linkedin.com/oauth/v2/authorization',
        token_url: 'https://www.linkedin.com/oauth/v2/accessToken'
      }

      option :scope, 'openid profile email'

      uid { raw_info['sub'] }

      info do
        {
          email: raw_info['email'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          picture_url: raw_info['picture']
        }
      end

      extra { { 'raw_info' => raw_info } }

      def callback_url
        full_host + script_name + callback_path
      end

      def raw_info
        @raw_info ||= access_token.get('/v2/userinfo').parsed
      end
    end
  end
end

OmniAuth.config.add_camelization 'linkedin', 'LinkedIn'
