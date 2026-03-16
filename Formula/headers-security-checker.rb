class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.3"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.3/hsc-macos-amd64"
    sha256 "108c11d7692d0a2cffa4ce62a8dbc9d115ad44ca276669da0809809520916cf5"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.3/hsc-linux-amd64"
    sha256 "66f0d5f867491bec308f453943ab18ade098b2401ac8bb1f4c90a54892b6bf3b"
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
