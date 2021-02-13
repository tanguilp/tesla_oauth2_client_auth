defmodule TeslaOAuth2ClientAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :tesla_oauth2_client_auth,
      description: "Tesla middlewares for OAuth2 and OpenID Connect client authentication",
      version: "1.0.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      deps: deps(),
      package: package(),
      source_url: "https://github.com/tanguilp/tesla_oauth2_client_auth"
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
      {:jose_utils, "~> 0.2"},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false},
      {:tesla, "~> 1.0"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/tesla_oauth2_client_auth"}
    ]
  end
end
