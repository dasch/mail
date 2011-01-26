require 'net/http'
require 'net/https'
require 'hmac'
require 'hmac-sha2'
require 'base64'
require 'cgi'

module Mail
  # Based on Amazon-SES-Mailer by Adam Bronte (abronte).
  #
  # https://github.com/abronte/Amazon-SES-Mailer
  class AmazonSES
    def initialize(values)
      self.settings = { :host => nil,
                        :version => nil,
                        :aws_access => nil,
                        :aws_secret => nil,
                        :endpoint => nil
                      }.merge!(values)
    end

    attr_accessor :settings

    def deliver!(mail)
      @time = Time.now

      http = Net::HTTP.new(settings[:host], 443)
      http.use_ssl = true
      headers = { "x-amzn-authorization" => full_signature, "Date" =>  sig_timestamp}
      data = request_data(msg)

      http.post("/", data, headers)

      self
    end

    private

    def request_data(msg)
      data = CGI::escape(Base64::encode64(msg))
      time = CGI::escape(url_timestamp)

      "AWSAccessKeyId=#{settings[:aws_access]}&Action=SendRawEmail&" +
      "RawMessage.Data=#{data}&Timestamp=#{time}&Version=#{settings[:version]}"
    end

    def url_timestamp
      @time.gmtime.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    end

    def sig_timestamp 
      @time.gmtime.strftime('%a, %d %b %Y %H:%M:%S GMT')
    end

    def generate_sig
      msg = "#{sig_timestamp}"
      hmac = HMAC::SHA256.new(settings[:aws_secret])
      hmac.update(msg)
      Base64::encode64(hmac.digest).chomp
    end

    def full_signature
      "AWS3-HTTPS AWSAccessKey=#{settings[:aws_access]}, " +
      "Signature=#{generate_sig}, Algorithm=HmacSHA256"
    end
  end
end
