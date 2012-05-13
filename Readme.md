# rbDNS
rbDNS is a bindata wrapper around the dns protocol

at the moment it can serve and send dns requests, the plan is to wrap  this with a higher level class and abstract away from alot of the unnecessary stuff.

A quick and dirty example of a dns request is

```ruby

require 'socket'
s = UDPSocket.new
dnspacket = DNS::DNSPacket.new
dnspacket.header.id = 13370
dnspacket.header.rd = 1
dnspacket.header.qdcount = 1

dnspacketquestion = DNS::DNSPacketQuestion.new
dnspacketquestion.qtype = DNS::QTYPE::A
dnspacketquestion.qclass = DNS::ACLASS::IN
dnspacketquestion.name = DNS::QName.from_str("www.google.com")
dnspacket.queries = [dnspacketquestion]


s.send(dnspacket.to_binary_s, 0, '8.8.8.8', 53)

text, sender = s.recvfrom(1024)
resp = DNS::DNSPacket.read(text)
resp.answers.each do |answer|
    puts answer.rdata
end

```

and serving a dns entry


```ruby

require 'socket'
s = UDPSocket.new
s.bind(nil, 53)
text, sender = s.recvfrom(1024)

# Parse the packet
packet = DNS::DNSPacket.read(text)

# respond
response = DNS::DNSPacket.new
response.header.id = packet.header.id
response.header.qr = 1
response.header.rd = 1
response.header.ra = 1
response.header.qdcount = 1
response.header.ancount = 1
response.queries = packet.queries

# a A response
answerpacket = DNS::DNSPacketResourceRecord.new
answerpacket.name = packet.queries[0].name
answerpacket.type = DNS::TYPE::A
answerpacket.aclass = DNS::ACLASS::IN
answerpacket.ttl = 86213
answerpacket.rdlength = 24
answerpacket.rdata = [127, 0, 0, 1]

response.answers = [ answerpacket ]

s.send(response.to_binary_s, 0, sender[3], sender[1])
```