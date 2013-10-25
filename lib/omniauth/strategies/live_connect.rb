require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LiveConnect < OmniAuth::Strategies::OAuth2
      BASE_SCOPE_URL = "https://apis.live.net/v5.0/"
      DEFAULT_SCOPE = 'wl.basic,wl.emails'

      option :name, 'live_connect'

      option :authorize_options, [:access_type, :hd, :login_hint, :prompt, :scope, :state, :redirect_uri]
      
      option :client_options, {
        :site => 'https://login.live.com',
        :authorize_url => '/oauth20_authorize.srf',
        :token_url => '/oauth20_token.srf'
      }


      def initialize(app, client_id=nil, client_secret=nil)

        options = {
          }.merge(options)

        @client_id = client_id
        @client_secret = client_secret


          super(app, :live_connect, client_id, client_secret)
        end

        def authorize_params
          super.tap do |params|

            params[:client_id] = @client_id

            params[:scope] = DEFAULT_SCOPE

            params[:response_type] = 'code'

            session['omniauth.state'] = params[:state] if params['state']
          end
        end

        uid { raw_info['id'].to_s }

        info do
          {
            'name' => raw_info['name'],
            'first_name' => raw_info['first_name'],
            'last_name' => raw_info['last_name'],
            'email' => raw_info['emails']['preferred']
          }
        end

        extra do
          {:raw_info => raw_info}
        end

        def raw_info
          @raw_info ||= access_token.get('https://apis.live.net/v5.0/me').parsed
        end

      end
    end
  end
