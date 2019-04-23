require 'rack/auth/request'
require 'rack/auth/nginx_omniauth_adapter/version'
require 'net/https'

module Rack
  module Auth
    class NginxOmniauthAdapter
      class Callback
        def initialize(app, auth_host:, callback_path: '/_auth/callback')
          @app, @auth_host, @callback_path = app, auth_host, callback_path
        end

        def call(env)
          if env['REQUEST_URI'].split(??, 2)[0] == @callback_path
            https = Net::HTTP.new(@auth_host, 443)
            https.use_ssl = true
            req = Net::HTTP::Get.new("/callback?#{env['QUERY_STRING']}")

            response = https.request(req)
            return [ response.code.to_i, response.to_hash, [ response.body ] ]
          end

          @app.call(env)
        end
      end

      class Initiate
        def initialize(app, auth_host:, callback_path: '/_auth/callback')
          @app, @auth_host, @callback_path = app, auth_host, callback_path
        end

        def call(env)
          res = @app.call(env)

          if res[0].to_i == 401
            https = Net::HTTP.new(@auth_host, 443)
            https.use_ssl = true
            req = Net::HTTP::Get.new('/initiate')
            req['x-ngx-omniauth-initiate-back-to'] = "https://#{env['HTTP_HOST']}#{env['REQUEST_URI']}"
            req['x-ngx-omniauth-initiate-callback'] = "https://#{env['HTTP_HOST']}#{@callback_path}"
            req['cookie'] = env['HTTP_COOKIE']

            response = https.request(req)
            return [ response.code.to_i, response.to_hash, [ response.body ] ]
          end

          res
        end
      end

      def initialize(app, auth_host:, callback_path: '/_auth/callback')
        @app, @auth_host, @callback_path = app, auth_host, callback_path
      end

      def call(env)
        request = Rack::Auth::Request.new @app do |env|
          https = Net::HTTP.new(@auth_host, 443)
          https.use_ssl = true
          req = Net::HTTP::Get.new('/test')
          req['x-ngx-omniauth-original-uri'] = "https://#{env['HTTP_HOST']}#{env['REQUEST_URI']}"
          req['cookie'] = env['HTTP_COOKIE']

          response = https.request(req)
          [ response.code.to_i, response.to_hash, [ response.body ] ]
        end
        initiate = Initiate.new(request, auth_host: @auth_host, callback_path: @callback_path)
        Callback.new(initiate, auth_host: @auth_host, callback_path: @callback_path)
      end
    end
  end
end
