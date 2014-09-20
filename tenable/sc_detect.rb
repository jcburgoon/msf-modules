##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Tenable SecurityCenter Detection Utility',
      'Description'    => 'This module attempts to detect Tenable\'s SecurityCenter.',
      'Author'         => [ 'Jesse Burgoon <jesse.burgoon[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptInt.new('THREADS', [true, "The number of concurrent threads", 16])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('SSL', [ true, "Negotiate SSL connections", true]),
        OptEnum.new('SSLVersion', [ false, 'Specify the version of SSL that should be used', 'TLS1', ['SSL2', 'SSL3', 'TLS1']])
      ], self.class)
  end

  def run_host(ip)
    begin
      res = send_request_cgi!({
        'method'  => 'GET'
        }, 15)
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        print_error("#{ip} - HTTP Connection Failed!")
        return
      end

      if res
        if res.body =~ /\<title\>Tenable/ and res.body =~ /js\/tenable.js\?version/
          print_good("#{ip} - SecurityCenter Detected")
          report_service(
            :host => ip,
            :port => datastore['RPORT'],
            :name => "sc",
            :info => 'Tenable SecurityCenter Detected',
            :state => 'open'
          )
        else
          print_error("#{ip} - Server is not SecurityCenter")
        end
      else
        print_error("#{ip} - No response!")
        return
      end
  end
end
