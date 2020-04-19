defmodule TeslaOAuth2ClientAuth.ClientSecretPost do
  @moduledoc """
  Tesla middleware that implements the `"client_secret_post"` authentication scheme for
  OAuth2 and OpenID Connect clients

  The client configuration must contain a `"client_secret"` member whose value is the
  client secret (a `String.t()`). Note that the body must be a map to be later serialized with
  the `Tesla.Middleware.FormUrlencoded`.

  Use of this authentication scheme is **not recommended**.
  """

  @behaviour Tesla.Middleware

  @impl true
  def call(%Tesla.Env{body: %{}} = env, next, opts) do
    client_id = opts[:client_id] || raise "Missing client id"
    client_secret = opts[:client_config]["client_secret"] || raise "Missing client secret`"

    body =
      env.body
      |> Map.put("client_id", client_id)
      |> Map.put("client_secret", client_secret)

    %Tesla.Env{env | body: body}
    |> Tesla.run(next)
  end
end
