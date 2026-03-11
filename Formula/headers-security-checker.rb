class HeadersSecurityChecker < Formula
  desc "High-performance command-line tool for security auditing of HTTP response headers"
  homepage "https://github.com/NonBytes/Headers-Security-Checker"
  version "0.1.1"

  if OS.mac?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.1/headers_security_checker-macos-amd64"
    sha256 "c3f27c67ea531a25108bc0618147bc9cebf624795149d6d8d53803b71d9f4b4a"
  elsif OS.linux?
    url "https://github.com/NonBytes/Headers-Security-Checker/releases/download/v0.1.1/headers_security_checker-linux-amd64"
    sha256 "6a9d0202226450252bcd46587edd9389d7e4b47d13401f8f1ae520f3cbf763b4"
  end

  def install
    if OS.mac?
      bin.install "headers_security_checker-macos-amd64" => "hsc"
    elsif OS.linux?
      bin.install "headers_security_checker-linux-amd64" => "hsc"
    end
  end

  test do
    system "#{bin}/hsc", "--help"
  end
end
