class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.2"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.2/hsc-macos-amd64"
    sha256 "17bfd36ebd5a5c2c7dcf1b9f7d066119ca4133adb6c28bf8b558f6651bdecba8"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.2/hsc-linux-amd64"
    sha256 "17bfd36ebd5a5c2c7dcf1b9f7d066119ca4133adb6c28bf8b558f6651bdecba8"
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
