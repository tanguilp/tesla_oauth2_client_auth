defmodule TeslaOAuth2ClientAuth.None do
  @moduledoc """
  Tesla middleware that implements the `"none"` authentication scheme for
  OAuth2 and OpenID Connect clients

  Basically, does not do anything.
  """

  @behaviour Tesla.Middleware

  @impl true
  def call(env, next, _opts) do
    Tesla.run(env, next)
  end
end
