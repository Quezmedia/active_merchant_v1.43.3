require 'active_merchant'
require 'support/gateway_support'

class SSLVerify

  def initialize
    @gateways = GatewaySupport.new.gateways
  end

  def test_gateways
    success, failed, missing, errored, disabled = [], [], [], [], []

    puts "Verifying #{@gateways.count} SSL certificates\n\n"

    @gateways.each do |g|
      if !g.live_url
        missing << g unless g.abstract_class
        next
      end

      if !g.ssl_strict
        disabled << g
      end

      uri = URI.parse(g.live_url)
      result,message = ssl_verify_peer?(uri)
      case result
      when :success
        print "."
        success << g
      when :fail
        print "F"
        failed << {:gateway => g, :message => message}
      when :error
        print "E"
        errored << {:gateway => g, :message => message}
      end
    end

    puts "\n\n\nFailed Gateways:"
    failed.each do |f|
      puts "#{f[:gateway].name} - #{f[:message]}"
    end

    puts "\n\nError Gateways:"
    errored.each do |e|
      puts "#{e[:gateway].name} - #{e[:message]}"
    end

    if missing.size > 0
      puts "\n\nGateways missing live_url:"
      missing.each do |m|
        puts m.name
      end
    end

    if disabled.size > 0
      puts "\n\nGateways with ssl_strict=false:"
      disabled.each do |d|
        puts d.name
      end
    end

  end

  def try_host(http, path)
    http.get(path)
  rescue Net::HTTPBadResponse, EOFError, SocketError
    http.post(path, "")
  end

  def ssl_verify_peer?(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    ca_file_path = File.dirname(__FILE__) + '/certs/cacert.pem'
  
    # Fallback to ENV['SSL_CERT_FILE'] if the default ca_file is not present
    if File.exist?(ca_file_path)
      http.ca_file = ca_file_path
      puts "Using CA file from gem: #{ca_file_path}"
    elsif ENV['SSL_CERT_FILE'] && File.exist?(ENV['SSL_CERT_FILE'])
      http.ca_file = ENV['SSL_CERT_FILE']
      puts "Using CA file from ENV['SSL_CERT_FILE']: #{ENV['SSL_CERT_FILE']}"
    else
      puts "CA file not found. Proceeding without explicit CA file."
    end
  
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.open_timeout = 60
    http.read_timeout = 60
  
    begin
      response = if uri.path.blank?
                   try_host(http, "/")
                 else
                   try_host(http, uri.path)
                 end
  
      puts "SSL verification succeeded. Response code: #{response.code}"
      return :success
    rescue OpenSSL::SSL::SSLError => ex
      puts "SSL verification failed: #{ex.message}"
      return :fail, ex.inspect
    rescue Net::HTTPBadResponse, Errno::ETIMEDOUT, EOFError, SocketError, Errno::ECONNREFUSED, Timeout::Error => ex
      puts "HTTP request failed: #{ex.message}"
      return :error, ex.inspect
    end
  end
end
