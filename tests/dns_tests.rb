#!/usr/bin/env ruby

require_relative '../lib/dns'
require 'turn/autorun'

class TestRBDNS < MiniTest::Unit::TestCase

  def test_labels_www
    assert_equal "www", DNS::Label.read("\x03www").data
    assert_equal 3, DNS::Label.read("\x03www").len
    assert_equal "www", DNS::Label.read("\x03wwwkdwopwdwq").data
  end
    
  def test_labels_empty
    assert_equal "", DNS::Label.read("\x00").data
    assert_equal 0, DNS::Label.read("\x00").len
  end

  def test_qnames_google
    BinData::trace_reading do
      assert_equal "\x03www\x06google\x03com\x00", DNS::QName.read("\x03www\x06google\x03com\x00").to_binary_s
      assert_equal "www.google.com", DNS::QName.read("\x03www\x06google\x03com\x00").to_str

      assert_equal "\x03www\x06google\x03com\x00", DNS::QName.from_str("www.google.com").to_binary_s
      assert_equal "www.google.com", DNS::QName.from_str("www.google.com").to_str
    end
  end

  def test_qnames_empty
    assert_equal "\x00", DNS::QName.read("\x00").to_binary_s
    assert_equal "\x00", DNS::QName.from_str("").to_binary_s
    assert_equal "", DNS::QName.from_str("").to_str
  end

  def test_qnames_9A
    assert_equal "#{'A'*9}B", DNS::QName.from_str("#{'A'*9}B").to_str
    assert_equal "\x0A#{'A'*9}C\x00", DNS::QName.read("\x0A#{'A'*9}C\x00").to_binary_s
    assert_equal "#{'A'*9}D", DNS::QName.read("\x0A#{'A'*9}D\x00").to_str
  end

  def test_qnames_29A
    assert_equal "#{'A'*29}B", DNS::QName.from_str("#{'A'*29}B").to_str
    assert_equal "\x1e#{'A'*29}C\x00", DNS::QName.read("\x1e#{'A'*29}C\x00").to_binary_s
    assert_equal "#{'A'*29}D", DNS::QName.read("\x1e#{'A'*29}D\x00").to_str
  end

  def test_qnames_49A
    assert_equal "#{'A'*49}B", DNS::QName.from_str("#{'A'*49}B").to_str
    assert_equal "\x32#{'A'*49}C\x00", DNS::QName.read("\x32#{'A'*49}C\x00").to_binary_s
    assert_equal "#{'A'*49}D", DNS::QName.read("\x32#{'A'*49}D\x00").to_str  
  end

  def test_qnames_69A
    # >63 should not match
    assert_raises ArgumentError do
      DNS::QName.from_str("#{'A'*69}B").to_str
    end
    assert_raises ArgumentError do
      skip "TODO: Raise error when reading a label too large from user input"
      DNS::QName.read("\x46#{'A'*69}C\x00").to_binary_s
    end
    assert_raises ArgumentError do
      skip "TODO: Raise error when reading a label too large from user input"
      DNS::QName.read("\x46#{'A'*69}D\x00").to_str
    end
  end

  def test_resolve_google
    require 'socket'
    BinData::trace_reading do
      puts "Creating query packet for ACLASS:IN/QTYPE:A www.google.com:"
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

      p dnspacket

      s.send(dnspacket.to_binary_s, 0, '8.8.8.8', 53)
      puts "Response:"
      text, sender = s.recvfrom(1024)

      resp = DNS::DNSPacket.read(text)
      p resp
      #resp.answers.each do |seg|
      #   if seg.type == DNS::TYPE::CNAME
      #     seg.rdata = "a"
      #   end

      #   if seg.name.name.value.class == Fixnum # pointer
      #     #puts "--"
      #     seg.name.name = DNS::QName.read(text[seg.name.name.value..-1])
      #   end
      # end
    end
  end
end