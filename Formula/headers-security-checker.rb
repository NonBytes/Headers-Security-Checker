class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.5"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.5/hsc-macos-amd64"
    sha256 "53f44824d89e341f3950bd513ba4a95a07678c92de2cba0ae31fbbaa34fd84c5"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.5/hsc-linux-amd64"
    sha256 "32ec8e367c188201e8a31669daee88dda2da64124989206c69dea29f3d6c498c"
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
