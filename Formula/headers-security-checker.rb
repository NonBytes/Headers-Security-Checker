class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.4"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.4/hsc-macos-amd64"
    sha256 "596bf19187806ca366f1175b15826cb8599e4d75d3ae59a547852379cf94f8e3"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.4/hsc-linux-amd64"
    sha256 "4f9668b69ce63a960d1b6e85b4a39b1dc3527ba6ce9289c15d100a75868ed47b"
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
