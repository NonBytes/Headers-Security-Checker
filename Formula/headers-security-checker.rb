class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.6"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.6/hsc-macos-amd64"
    sha256 "787b12ef39ef551e08454bc0a1312d0b6584d47119e0eb167e5d5441bb74f4c7"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.6/hsc-linux-amd64"
    sha256 "da7376f280c052eebb1112f06729afa9a47f901f5c808dc64ecc31b4d9c8de6a"
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
