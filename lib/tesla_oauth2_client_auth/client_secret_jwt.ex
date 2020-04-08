defmodule TeslaOAuth2ClientAuth.ClientSecretJWT do
  @moduledoc """
  Tesla middleware that implements the `"client_secret_jwt"` authentication scheme for
  [https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication](OpenID Connect clients)

  The client configuration must contain a `"client_secret"` member whose value is the
  client secret (a `String.t()`). Note that the body must be a map to be later serialized with
  the `Tesla.Middleware.FormUrlencoded`.

  The options of this middleware are:
  - `:jwt_lifetime`: the lifetime of the JWT in seconds. Defaults to `30`
  - `:jwt_mac_alg`: the algorithm to MAC the JWTs. One of `"HS256"`, `"HS384"` and `"HS512"`.
  Defaults to `"HS256"`
  - `:jwt_jti_callback`: a `(TeslaOAuth2ClientAuth.opts() -> String.t())` function that returns
  the `"jti"` field of the JWT. Defaults to a random 16-bytes base64 encoded string
  - `:jwt_additional_claims`: claims added to the JWT. They have precedence over the default
  claims
  """

  @behaviour Tesla.Middleware

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  @impl true
  def call(%Tesla.Env{body: %{}} = env, next, opts) do
    client_id = opts[:client_id] || raise "Missing client id"

    body =
      env.body
      |> Map.put("client_id", client_id)
      |> Map.put("client_assertion_type", @assertion_type)
      |> Map.put("client_assertion", build_assertion(opts))

    %Tesla.Env{env | body: body}
    |> Tesla.run(next)
  end

  defp build_assertion(opts) do
    client_id = opts[:client_id] || raise "Missing client id"
    client_secret = opts[:client_config]["client_secret"] || raise "Missing client secret`"
    issuer = opts[:server_metadata]["issuer"] || raise "Missing issuer from server metadata"
    lifetime = opts[:jwt_lifetime] || 30
    mac_alg = opts[:jwt_mac_alg] || "HS256"

    jti =
      case opts[:jwt_jti_callback] do
        callback when is_function(callback, 1) ->
          callback.(opts)

        nil ->
          gen_jti()
      end

    message =
      %{
        iss: client_id,
        sub: client_id,
        aud: issuer,
        jti: jti,
        exp: now() + lifetime,
        iat: now()
      }
      |> Map.merge(opts[:jwt_additional_claims] || %{})
      |> Jason.encode!()

    JOSE.JWK.from(%{"k" => Base.url_encode64(client_secret, padding: false), "kty" => "oct"})
    |> JOSE.JWS.sign(message, %{"alg" => mac_alg})
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp gen_jti(), do: :crypto.strong_rand_bytes(16) |> Base.encode64(padding: false)

  defp now(), do: System.system_time(:second)
end
