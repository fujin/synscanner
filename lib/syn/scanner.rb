require 'bundler'
Bundler.require

require 'benchmark'

module Syn
  class Scanner

    attr_accessor :capture, :arp_capture, :arp_cache, :dst_cache

    def datastore
      @datastore ||= {
        "PORTS" => "80",
        "TIMEOUT" => 200,
        "UDP_SECRET" => rand(1000)
      }
    end

    #
    # Opens a handle to the specified device
    #
    def open_pcap(opts={})
      if RUBY_PLATFORM == "i386-mingw32"
        if opts['INTERFACE'] or datastore['INTERFACE']
          dev = opts['INTERFACE'] || datastore['INTERFACE']
          if is_interface?(dev)
            dev = get_interface_guid(dev)
          end
        end
      else
        dev = opts['INTERFACE'] || datastore['INTERFACE'] || nil
      end

      len = (opts['SNAPLEN'] || datastore['SNAPLEN']  || 65535).to_i
      tim = (opts['TIMEOUT'] || datastore['TIMEOUT']  || 0).to_i
      fil = opts['FILTER'] || datastore['FILTER']
      arp = opts['ARPCAP'] || true

      dev ||= ::Pcap.lookupdev

      unless RUBY_PLATFORM == "i386-mingw32"
        system("ifconfig", dev, "up")
      end

      self.capture = ::Pcap.open_live(dev, len, true, tim)
      if arp
        self.arp_capture = ::Pcap.open_live(dev, 512, true, tim)
        preamble = datastore['UDP_SECRET'].to_i
        arp_filter = "arp[6:2] = 2 or (udp[8:4] = #{preamble})"
        self.arp_capture.setfilter(arp_filter)
      end

      if (not self.capture)
        raise RuntimeError, "Could not start the capture process"
      elsif (arp and !self.arp_capture and cap.empty?)
        raise RuntimeError, "Could not start the ARP capture process"
      end

      self.capture.setfilter(fil) if fil
    end

    def close_pcap
      return if not self.capture
      self.capture = nil
      self.arp_capture = nil
      GC.start()
    end

    def initialize()
      open_pcap
      hosts = %w[169.254.169.254]
      puts Benchmark.measure { run_batch(hosts) }
    end

    def run_batch(hosts)
      open_pcap

      pcap = self.capture

      ports = Rex::Socket.portspec_crack(datastore['PORTS'])

      if ports.empty?
        puts("Error: No valid ports specified")
        return
      end

      to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

      # Spread the load across the hosts
      ports.each do |dport|
        hosts.each do |dhost|
          shost, sport = getsource(dhost)
          self.capture.setfilter(getfilter(shost, sport, dhost, dport))
          probe = buildprobe(shost, sport, dhost, dport)
          capture_sendto(probe, dhost)
          reply = probereply(self.capture, to)

          next if not reply

          if (reply.is_tcp? and reply.tcp_flags.syn == 1 and reply.tcp_flags.ack == 1)
            puts("TCP OPEN #{dhost}:#{dport}")
          end

        end
      end

      close_pcap
    end

    def getfilter(shost, sport, dhost, dport)
      # Look for associated SYN/ACKs and RSTs
      "tcp and (tcp[13] == 0x12 or (tcp[13] & 0x04) != 0) and " +
        "src host #{dhost} and src port #{dport} and " +
        "dst host #{shost} and dst port #{sport}"
    end

    def getsource(dhost)
      # srcip, srcport
      [ Rex::Socket.source_address(dhost), rand(0xffff - 1025) + 1025 ]
    end

    def buildprobe(shost, sport, dhost, dport)
      p = PacketFu::TCPPacket.new
      p.ip_saddr = shost
      p.ip_daddr = dhost
      p.tcp_sport = sport
      p.tcp_flags.ack = 0
      p.tcp_flags.syn = 1
      p.tcp_dport = dport
      p.tcp_win = 3072
      p.recalc
      p
    end

    def probereply(pcap, to)
      reply = nil
      begin
        Timeout.timeout(to) do
          pcap.each do |r|
            pkt = PacketFu::Packet.parse(r)
            next unless pkt.is_tcp?
            reply = pkt
            break
          end
        end
      rescue Timeout::Error
      end
      return reply
    end

    # Capture_sendto is intended to replace the old Rex::Socket::Ip.sendto method. It requires
    # a payload and a destination address. To send to the broadcast address, set bcast
    # to true (this will guarantee that packets will be sent even if ARP doesn't work
    # out).
    def capture_sendto(payload="", dhost=nil, bcast=false, dev=nil)
      raise RuntimeError, "Could not access the capture process (remember to open_pcap first!)" unless self.capture
      raise RuntimeError, "Must specify a host to sendto" unless dhost
      dev ||= datastore['INTERFACE']
      dst_mac,src_mac = lookup_eth(dhost,dev)
      if dst_mac == nil and not bcast
        return false
      end
      inject_eth(:payload => payload, :eth_daddr => dst_mac, :eth_saddr => src_mac)
    end

    def inject(pkt="",pcap=self.capture)
      if not pcap
        raise RuntimeError, "Could not access the capture process (remember to open_pcap first!)"
      else
        pcap.inject(pkt.to_s) # Can be a PacketFu Packet object or a pre-packed string
      end
    end

    def inject_eth(args={})
      eth_daddr = args[:eth_daddr] || "ff:ff:ff:ff:ff:ff"
      eth_saddr = args[:eth_saddr] || "00:00:00:00:00:00"
      eth_type  = args[:eth_type]  || 0x0800 # IP default
      payload   = args[:payload]
      pcap      = args[:pcap]      || self.capture
      p = PacketFu::EthPacket.new
      p.eth_daddr = eth_daddr
      p.eth_saddr = eth_saddr
      p.eth_proto = eth_type
      if payload
        if payload.kind_of? PacketFu::EthPacket
          p.payload = payload.eth_header.body
        elsif payload.kind_of? PacketFu::EthHeader
          p.payload = payload.body
        else
          p.payload = payload.to_s
        end
      end
      inject p.to_s,pcap
    end


    def lookup_eth(addr=nil,iface=nil)
      raise RuntimeError, "Could not access the capture process." if not self.arp_capture

      self.arp_cache ||= {}
      self.dst_cache ||= {}

      return self.dst_cache[addr] if self.dst_cache[addr]

      if !self.arp_cache[Rex::Socket.source_address(addr)]
        probe_gateway(addr)
      end

      src_mac = self.arp_cache[Rex::Socket.source_address(addr)]
      if should_arp?(addr)
        dst_mac = self.arp_cache[addr] || arp(addr)
      else
        dst_mac = self.arp_cache[:gateway]
      end

      self.dst_cache[addr] = [dst_mac,src_mac]
    end

    def probe_gateway(addr)
      dst_host = (datastore['GATEWAY'] || IPAddr.new((rand(16777216) + 2969567232), Socket::AF_INET).to_s)
      dst_port = rand(30000)+1024
      preamble = [datastore['UDP_SECRET']].pack("N")
      secret = "#{preamble}#{Rex::Text.rand_text(rand(0xff)+1)}"
      UDPSocket.open.send(secret,0,dst_host,dst_port)
      begin
        to = (datastore['TIMEOUT'] || 1500).to_f / 1000.0
        ::Timeout.timeout(to) do
          while(my_packet = inject_reply(:udp,self.arp_capture))
            if my_packet.payload == secret
              dst_mac = self.arp_cache[:gateway] = my_packet.eth_daddr
              src_mac = self.arp_cache[Rex::Socket.source_address(addr)] = my_packet.eth_saddr
              return [dst_mac,src_mac]
            else
              next
            end
          end
        end
      rescue ::Timeout::Error
        # Well, that didn't work (this common on networks where there's no gatway, like
        # VMWare network interfaces. We'll need to use a fake source hardware address.
        self.arp_cache[Rex::Socket.source_address(addr)] = "00:00:00:00:00:00"
      end
    end

    def inject_reply(proto=:udp,pcap=self.capture)
      reply = nil
      to = (datastore['TIMEOUT'] || 500).to_f / 1000.0
      if not pcap
        raise RuntimeError, "Could not access the capture process (remember to open_pcap first!)"
      else
        begin
          ::Timeout.timeout(to) do
            pcap.each do |r|
              packet = PacketFu::Packet.parse(r)
              next unless packet.proto.map {|x| x.downcase.to_sym}.include? proto
              reply = packet
              break
            end
          end
        rescue ::Timeout::Error
        end
      end
      return reply
    end

    def should_arp?(ip)
      @mydev  ||= datastore['INTERFACE'] || ::Pcap.lookupdev
      @mymask ||= datastore['NETMASK'] || 24
      @mynet  ||= lookupnet
      @mynet.include?(IPAddr.new(ip))
    end

    def lookupnet
      dev  = datastore['INTERFACE'] || ::Pcap.lookupdev
      mask = datastore['NETMASK'] || 24
      begin
        my_net = IPAddr.new("#{Pcap.lookupnet(dev).first}/#{mask}")
      rescue RuntimeError => e
        @pcaprub_error = e
        puts("Cannot stat device: #{@pcaprub_error}")
        raise RuntimeError, "Pcaprub error: #{@pcaprub_error}"
      end
      return my_net
    end

  end
end
