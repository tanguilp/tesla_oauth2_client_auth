defmodule TeslaOAuth2ClientAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :tesla_oauth2_client_auth,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:jason, "~> 1.2"},
      {:jose, "~> 1.10.1"},
      {:jose_utils, path: "../jose_utils"},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false},
      {:tesla, "~> 1.3.0"}
    ]
  end
end
