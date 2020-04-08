defmodule TeslaOAuth2ClientAuth.ClientSecretBasic do
  @moduledoc """
  Tesla middleware that implements the `"client_secret_basic"` authentication scheme for
  OAuth2 and OpenID Connect clients

  The client configuration must contain a `"client_secret"` member whose value is the
  client secret (a `String.t()`).
  """

  @behaviour Tesla.Middleware

  @impl true
  def call(env, next, opts) do
    client_id = opts[:client_id] || raise "Missing client id"
    client_secret = opts[:client_config]["client_secret"] || raise "Missing client secret`"

    header_value = "Basic " <> Base.encode64(client_id <> ":" <> client_secret)

    env
    |> Tesla.put_header("authorization", header_value)
    |> Tesla.run(next)
  end
end
