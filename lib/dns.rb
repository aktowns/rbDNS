#
# Copyright (C) 2012 Ashley Towns
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
# files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished 
# to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

#
# These set of classes wrap the DNS Protocol loosely, in order to provide basic functionality for a DNS Server or Client
# Use at your own peril.
#
# TODO: Make responses use QName pointers (1035/4.1.4. Message compression)

require 'bindata'

# RFC 1035
# All communications inside of the domain protocol are carried in a single
# format called a message.  The top level format of message is divided
# into 5 sections (some of which are empty in certain cases) shown below:

#     +---------------------+
#     |        Header       |
#     +---------------------+
#     |       Question      | the question for the name server
#     +---------------------+
#     |        Answer       | RRs answering the question
#     +---------------------+
#     |      Authority      | RRs pointing toward an authority
#     +---------------------+
#     |      Additional     | RRs holding additional information
#     +---------------------+
module DNS

  class Label < BinData::Record
    uint8 :len
    string :data, :read_length => :len
  end

  # The pointer takes the form of a two octet sequence:

  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     | 1  1|                OFFSET                   |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  # The first two bits are ones.  This allows a pointer to be distinguished
  # from a label, since the label must begin with two zero bits because
  # labels are restricted to 63 octets or less.  (The 10 and 01 combinations
  # are reserved for future use.)  The OFFSET field specifies an offset from
  # the start of the message (i.e., the first octet of the ID field in the
  # domain header).  A zero offset specifies the first byte of the ID field,
  # etc.
  class QNamePointer < BinData::Primitive
    bit2 :ignore
    bit14 :val

    def get
      self.val.to_i
    end
  end

  # QNAME           a domain name represented as a sequence of labels, where
  #                 each label consists of a length octet followed by that
  #                 number of octets.  The domain name terminates with the
  #                 zero length octet for the null label of the root.  Note
  #                 that this field may be an odd number of octets; no
  #                 padding is used.
  class QName < BinData::Record
    # TODO: QName's can be a mix of labels and pointers, not sure if this should be a record instead
    endian :big

    array :name, :read_until => lambda { (element["len"] == 0 || element["len"] > 63) } do
      uint8 :len
      #string :data, :read_length => :len
      choice :data, :selection => lambda { len > 63 ? 1 : 0 } do
        string 0, :read_length => :len
        QNamePointer 1, :val => :len, :read_length => :len
      end
    end

    def to_str
      self.name.to_a.map{|x|x[:data]}.join(".")[0..-2]
    end

    def self.from_str(v)
      QName.read((v.split(".").map do |octet| 
        throw "Label too big" if octet.size > 63 
        octet.size.chr + octet
      end << "\x00").join)
    end
  end

  # Infer wether or not we're dealing with a QName or a pointer to
  # TODO: clean this up
  # class QNameOrPointer < BinData::Record
  #   array :len, :type => :bit1, :read_until => lambda { index == 1 }
  #   choice :name, :copy_on_change => true, :selection => lambda { len == [1,1] ? 1 : 0 } do
  #     QName 0
  #     QNamePointer 1
  #   end
  # end


  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ADDRESS                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  # where:

  # ADDRESS         A 32 bit Internet address.

  # Hosts that have multiple Internet addresses will have multiple A
  # records
  class Address < BinData::Primitive
    endian :big

    uint8 :one
    uint8 :two
    uint8 :three
    uint8 :four

    def set(v) 
      tmp = v.split(".")
      self.one = tmp[0].to_i
      self.two = tmp[1].to_i
      self.three = tmp[2].to_i
      self.four = tmp[3].to_i
    end

    def get
      "#{self.one}.#{self.two}.#{self.three}.#{self.four}"
    end
  end


  # The header contains the following fields:

  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      ID                       |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    QDCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ANCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    NSCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ARCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  class DNSPacketHeader < BinData::Record
    endian :big

    bit16 :id
    bit1  :qr
    bit4  :opcode
    bit1  :aa
    bit1  :tc
    bit1  :rd
    bit1  :ra
    bit3  :z, :initial_value => 0x000
    bit4  :rcode
    uint16 :qdcount
    uint16 :ancount 
    uint16 :nscount
    uint16 :arcount
  end

  # The question section is used to carry the "question" in most queries,
  # i.e., the parameters that define what is being asked.  The section
  # contains QDCOUNT (usually 1) entries, each of the following format:

  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                     QNAME                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QTYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QCLASS                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  class DNSPacketQuestion < BinData::Record
    QName :name
    bit16 :qtype
    bit16 :qclass
  end

  # The answer, authority, and additional sections all share the same
  # format: a variable number of resource records, where the number of
  # records is specified in the corresponding count field in the header.
  # Each resource record has the following format:

  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                                               /
  #     /                      NAME                     /
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     CLASS                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TTL                      |
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                   RDLENGTH                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  #     /                     RDATA                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  class DNSPacketResourceRecord < BinData::Record
    endian :big

    QName :name
    bit16 :type
    bit16 :aclass
    uint32 :ttl
    uint16 :rdlength
    choice :rdata, :selection => lambda { self["type"] } do
      Address 1, :read_length => :rdlength
      QName 5, :read_length => :rdlength
    end
    
  end

  class DNSPacket < BinData::Record
    endian :big

    DNSPacketHeader :header

    array :queries, :initial_length => lambda { header["qdcount"] } do
      DNSPacketQuestion :query
    end

    array :answers, :initial_length => lambda { header["ancount"] } do
      DNSPacketResourceRecord :answer
    end

    array :authorities, :initial_length => lambda { header["nscount"] } do
      DNSPacketResourceRecord :authority
    end

    array :additional, :initial_length => lambda { header["arcount"] } do
      DNSPacketResourceRecord :addition
    end
  end

  # Constants

  # TYPE fields are used in resource records.
  # RFC1035 - 3.2.2
  module TYPE
    A       = 1     # a host address

    NS      = 2     # an authoritative name server

    MD      = 3     # a mail destination (Obsolete - use MX)

    MF      = 4     # a mail forwarder (Obsolete - use MX)

    CNAME   = 5     # the canonical name for an alias

    SOA     = 6     # marks the start of a zone of authority

    MB      = 7     # a mailbox domain name (EXPERIMENTAL)

    MG      = 8     # a mail group member (EXPERIMENTAL)

    MR      = 9     # a mail rename domain name (EXPERIMENTAL)

    NULL    = 10    # a null RR (EXPERIMENTAL)

    WKS     = 11    # a well known service description

    PTR     = 12    # a domain name pointer

    HINFO   = 13    # host information

    MINFO   = 14    # mailbox or mail list information

    MX      = 15    # mail exchange

    TXT     = 16    # text strings
  end

  # QTYPE fields appear in the question part of a query.  QTYPES are a superset of TYPEs, hence all TYPEs are valid QTYPEs.
  # RFC1035 - 3.2.3
  module QTYPE
    include TYPE

    AXFR    = 252   # A request for a transfer of an entire zone

    MAILB   = 253   # A request for mailbox-related records (MB, MG or MR)

    MAILA   = 254   # A request for mail agent RRs (Obsolete - see MX)

    ASTERISK= 255   # A request for all records
  end

  # CLASS fields appear in resource records. 
  # RFC1035 - 3.2.4
  module ACLASS
    IN      = 1     # the Internet

    CS      = 2     # the CSNET class (Obsolete - used only for examples in some obsolete RFCs)

    CH      = 3     # the CHAOS class

    HS      = 4     # Hesiod [Dyer 87]
  end

  # QCLASS fields appear in the question section of a query.  QCLASS values are a superset of CLASS values; 
  # every CLASS is a valid QCLASS.
  # RFC1035 - 3.2.5
  module QCLASS
    include ACLASS

    ASTERISK= 255   # any class
  end

  # A four bit field that specifies kind of query in this message.  This value is set by the originator of a query
  # and copied into the response.
  # RFC1035 - 4.1.1
  module OPCODE
    QUERY   = 0     # a standard query

    IQUERY  = 1     # an inverse query

    STATUS  = 2     # a server status request
  end

  # Response code - this 4 bit field is set as part of responses.
  # RFC1035 - 4.1.1
  module RCODE
    NOERR     = 0   # No error condition

    FORMATERR = 1   # The name server was unable to interpret the query.

    SERVERFAIL= 2   # The name server was unable to process this query due to a problem with the name server.

    NAMEERR   = 3   # Meaningful only for responses from an authoritative name server, this code signifies that the
                    # domain name referenced in the query does not exist.
    NOTIMPL   = 4   # The name server does not support the requested kind of query.

    REFUSED   = 5   # The name server refuses to perform the specified operation for policy reasons.  For example, a name
                    # server may not wish to provide the information to the particular requester, or a name server may not 
                    # wish to perform a particular operation (e.g., zone transfer) for particular data.
  end
end


#def assert(l, r)
#  puts "Asserting '#{l.inspect}' == '#{r.inspect}'"
#  throw "Assertion Failed" if l != r
#end

#p DNS::QName.read("\x03www\x06google\x03com\x00")
# Test QName
#assert(DNS::QName.read("\x03www.google.com").to_binary_s, "\x03www\x06google\x03com\x00")


#require 'socket'
# Listen to a dns request, and respond
# s = UDPSocket.new
# s.bind(nil, 53)
# text, sender = s.recvfrom(1024)

# BinData::trace_reading do
#   # Parse the packet
#   packet          = DNS::DNSPacket.read(text)

#   # respond
#   response        = DNS::DNSPacket.new
#   response.header.id    = packet.header.id
#   response.header.qr    = 1
#   response.header.rd    = 1
#   response.header.ra    = 1
#   response.header.qdcount = 1
#   response.header.ancount = 1
#   response.queries    = packet.queries

#   # a CNAME response
#   answerpacket      = DNS::DNSPacketResourceRecord.new
#   answerpacket.name     = packet.queries[0].name
#   answerpacket.type     = DNS::TYPE::CNAME
#   answerpacket.aclass   = DNS::ACLASS::IN
#   answerpacket.ttl    = 86213
#   answerpacket.rdlength   = 24
#   answerpacket.rdata    = DNS::QName.new("7jguhsfwruviatqe.onion").to_binary_s

#   response.answers    = [ answerpacket ]
  
#   s.send(response.to_binary_s, 0, sender[3], sender[1])
# end

# Send a dns request
#BinData::trace_reading do


# puts "Creating query packet for ACLASS:IN/QTYPE:A www.google.com:"
#   s = UDPSocket.new
#   dnspacket = DNS::DNSPacket.new
#   dnspacket.header.id = 13370
#   dnspacket.header.rd = 1
#   dnspacket.header.qdcount = 1

#   dnspacketquestion = DNS::DNSPacketQuestion.new
#   dnspacketquestion.qtype = DNS::QTYPE::A
#   dnspacketquestion.qclass = DNS::ACLASS::IN
#   dnspacketquestion.name = DNS::QName.new("www.google.com")

#   dnspacket.queries = [dnspacketquestion]

#   p dnspacket

#   s.send(dnspacket.to_binary_s, 0, '8.8.8.8', 53)
#   puts "Response:"
#   text, sender = s.recvfrom(1024)

#   resp = DNS::DNSPacket.read(text)
#   resp.answers.each do |seg|
#     if seg.type == DNS::TYPE::CNAME
#       seg.rdata = "a"
#     end

#     if seg.name.name.value.class == Fixnum # pointer
#       #puts "--"
#       seg.name.name = DNS::QName.read(text[seg.name.name.value..-1])
#     end
#   end
#   p resp
#end 





