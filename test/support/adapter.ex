defmodule TeslaOAuth2ClientAuthTest.Adapter do
  @behaviour Tesla.Adapter

  @impl true
  def call(env, _options) do
    {:ok, env}
  end
end
