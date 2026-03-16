class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.7"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.7/hsc-macos-amd64"
    sha256 "356d56ce318b743dbb5e89a70a872124591aeb2549f00c2c59bf57846bcd9d40"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.7/hsc-linux-amd64"
    sha256 "1b84e564e3daeab99e03f15dd6da76b9b7948c51c1dd29ff3526c493fbc2a2df"
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
