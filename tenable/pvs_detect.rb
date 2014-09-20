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
      'Name'           => 'Tenable PVS Detection Utility',
      'Description'    => 'This module attempts to detect Tenable\'s Passive Vuln. Scanner.',
      'Author'         => [ 'Jesse Burgoon <jesse.burgoon[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8835),
        OptInt.new('THREADS', [true, "The number of concurrent threads", 16])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('SSL', [ true, "Negotiate SSL connections", true])
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
        if res.headers['Server'] =~ /PVS/
          print_good("#{ip} - PVS Detected")
          report_service(
            :host => ip,
            :port => datastore['RPORT'],
            :name => "pvs",
            :info => 'Tenable PVS Detected',
            :state => 'open'
          )
        else
          print_error("#{ip} - Server is not PVS (header: #{res.headers['Server'] || ''})")
        end
      else
        print_error("#{ip} - No response!")
        return
      end
  end
end
