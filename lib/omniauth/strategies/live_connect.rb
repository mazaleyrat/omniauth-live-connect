require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LiveConnect < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'wl.basic,wl.emails'

      option :name, 'live_connect'
      option :client_options, {
        :site => 'https://login.live.com',
        :authorize_url => '/oauth20_authorize.srf',
        :token_url => '/oauth20_token.srf'
      }

      option :authorize_options, [:access_type, :hd, :login_hint, :prompt, :scope, :state, :redirect_uri, :client_id]

     def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end

          raw_scope = params[:scope] || DEFAULT_SCOPE
          scope_list = raw_scope.split(" ").map {|item| item.split(",")}.flatten
          scope_list.map! { |s| s =~ /^https?:\/\// ? s : "#{BASE_SCOPE_URL}#{s}" }
          params[:scope] = scope_list.join(" ")
          params[:access_type] = 'offline' if params[:access_type].nil?

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
