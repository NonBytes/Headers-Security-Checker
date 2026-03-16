class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.8"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.8/hsc-macos-amd64"
    sha256 "3915ca0ae39e80896c92a1bc560a5c816053d59b0ca1b05d3251270a9c3e1e26"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.8/hsc-linux-amd64"
    sha256 "c75b3d3f95faf5922eeac4b491cdd2771ab1e3bfba7d612ec7529e6d65afa1d3"
  end

  def install
    if OS.mac?
      bin.install "hsc-macos-amd64" => "hsc"
    elsif OS.linux?
      bin.install "hsc-linux-amd64" => "hsc"
    end
  end

  test do
    system "#{bin}/hsc", "--help"
  end
end
