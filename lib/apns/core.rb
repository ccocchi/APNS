# Copyright (c) 2009 James Pozdena, 2010 Justin.tv
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  class Configuration
    attr_accessor :name, :pem, :pass, :cache

    def initialize
      @cache = false
    end
  end

  # Host for push notification service
  # production: gateway.push.apple.com
  # development: gateway.sandbox.apple.com
  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195

  # Host for feedback service
  # production: feedback.push.apple.com
  # development: feedback.sandbox.apple.com
  @feedback_host = 'feedback.sandbox.push.apple.com'
  @feedback_port = 2196

  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts

  @configurations = {}
  @cache_connections = {}
  @connections = {}

  class << self
    attr_accessor :host, :port, :feedback_host, :feedback_port, :pem, :pass, :cache_connections
  end

  def self.configure
    yield self
  end

  def self.add_connection
    c =  Configuration.new
    yield c
    @configurations[c.name] = [c.pem, c.pass]
    @cache_connections[c.name] = c.cache
  end

  def self.establish_notification_connection(connection_name)
    if @cache_connections[connection_name]
      begin
        self.get_connection(connection_name, self.host, self.port)
        return true
      rescue
      end
    end
    return false
  end

  def self.has_notification_connection?(connection_name)
    return self.has_connection?(connection_name)
  end

  def self.send_notification(device_token, message, connection_name = nil)
    self.with_notification_connection(connection_name) do |conn|
      conn.write(self.packaged_notification(device_token, message))
      conn.flush
    end
  end

  def self.send_notifications(notifications, connection_name = nil)
    self.with_notification_connection(connection_name) do |conn|
      notifications.each do |n|
        conn.write(self.packaged_notification(n[0], n[1]))
      end
      conn.flush
    end
  end

  def self.feedback
    apns_feedback = []
    self.with_feedback_connection do |conn|
      # Read buffers data from the OS, so it's probably not
      # too inefficient to do the small reads
      while data = conn.read(38)
        apns_feedback << self.parse_feedback_tuple(data)
      end
    end

    return apns_feedback
  end

  protected

  # Each tuple is in the following format:
  #
  #              timestamp | token_length (32) | token
  # bytes:  4 (big-endian)      2 (big-endian) | 32
  #
  # timestamp - seconds since the epoch, in UTC
  # token_length - Always 32 for now
  # token - 32 bytes of binary data specifying the device token
  #
  def self.parse_feedback_tuple(data)
    feedback = data.unpack('N1n1H64')
    {:feedback_at => Time.at(feedback[0]), :length => feedback[1], :device_token => feedback[2] }
  end

  def self.packaged_notification(device_token, message)
    pt = self.packaged_token(device_token)
    pm = self.packaged_message(message)
    [0, 0, 32, pt, 0, pm.size, pm].pack("ccca*cca*")
  end

  def self.packaged_token(device_token)
    [device_token.gsub(/[\s|<|>]/,'')].pack('H*')
  end

  def self.packaged_message(message)
    if message.is_a?(Hash)
      message.to_json
    elsif message.is_a?(String)
      '{"aps":{"alert":"'+ message + '"}}'
    else
      raise "Message needs to be either a hash or string"
    end
  end

  def self.with_notification_connection(connection_name, &block)
    self.with_connection(connection_name, self.host, self.port, &block)
  end

  def self.with_feedback_connection(&block)
    # Explicitly disable the connection cache for feedback
    cache_temp = @cache_connections
    @cache_connections = false

    self.with_connection(self.feedback_host, self.feedback_port, &block)

  ensure
    @cache_connections = cache_temp
  end

  private

  def self.open_connection(connection_name, host, port)
    if connection_name.nil?
      raise "No connection has been set" if @configurations.empty?
      pem, pass = @configurations.first
    else
      pem, pass = @configurations[connection_name]
    end

    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless pem
    raise "The path to your pem file does not exist!" unless File.exist?(pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(pem), pass)

    retries = 0
    begin
      sock         = TCPSocket.new(host, port)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock, context)
      ssl.connect
      return ssl, sock
    rescue SystemCallError
      if (retries += 1) < 5
        sleep 1
        retry
      else
        # Too many retries, re-raise this exception
        raise
      end
    end
  end

  def self.has_connection?(connection_name)
    @connections.has_key?(connection_name)
  end

  def self.create_connection(connection_name, host, port)
    @connections[connection_name] = self.open_connection(connection_name, host, port)
  end

  def self.find_connection(connection_name)
    @connections[connection_name]
  end

  def self.remove_connection(connection_name)
    if self.has_connection?(connection_name)
      ssl, sock = @connections.delete(connection_name)
      ssl.close
      sock.close
    end
  end

  def self.reconnect_connection(connection_name, host, port)
    self.remove_connection(connection_name)
    self.create_connection(connection_name, host, port)
  end

  def self.get_connection(connection_name, host, port)
    if @cache_connections[connection_name]
      # Create a new connection if we don't have one
      unless self.has_connection?(connection_name)
        self.create_connection(connection_name, host, port)
      end

      ssl, sock = self.find_connection(connection_name)
      # If we're closed, reconnect
      if ssl.closed?
        self.reconnect_connection(connection_name, host, port)
        self.find_connection(connection_name)
      else
        return [ssl, sock]
      end
    else
      self.open_connection(connection_name, host, port)
    end
  end

  def self.with_connection(connection_name, host, port, &block)
    retries = 0
    begin
      ssl, sock = self.get_connection(connection_name, host, port)
      yield ssl if block_given?

      unless @cache_connections[connection_name]
        ssl.close
        sock.close
      end
    rescue Errno::ECONNABORTED, Errno::EPIPE, Errno::ECONNRESET
      if (retries += 1) < 5
        self.remove_connection(connection_name)
        retry
      else
        # too-many retries, re-raise
        raise
      end
    end
  end
end
