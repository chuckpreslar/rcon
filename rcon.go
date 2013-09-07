package rcon

import (
  "bytes"
  "encoding/binary"
  "errors"
  "fmt"
  "net"
  "strings"
)

const (
  PACKET_PADDING_SIZE = 2
  PACKET_HEADER_SIZE  = 8
)

var (
  ErrInvalidWrite     = errors.New("Failed to write the payload corretly to remote connection.")
  ErrInvalidRead      = errors.New("Failed to read the response corretly from remote connection.")
  ErrInvalidChallenge = errors.New("Server failed to mirror request challenge.")
)

type Client struct {
  Host           string
  Port           int
  ChallengeIndex int
  Authorized     bool
  Connection     net.Conn
}

type Header struct {
  Size      int32
  Challenge int32
  Type      int32
}

type Packet struct {
  Header Header
  Body   string
}

func (p Packet) Compile() (payload []byte, err error) {
  var size int32 = p.Header.Size
  var buffer bytes.Buffer
  var padding [PACKET_PADDING_SIZE]byte

  if err = binary.Write(&buffer, binary.LittleEndian, &size); nil != err {
    return
  } else if err = binary.Write(&buffer, binary.LittleEndian, &p.Header.Challenge); nil != err {
    return
  } else if err = binary.Write(&buffer, binary.LittleEndian, &p.Header.Type); nil != err {
    return
  }

  buffer.WriteString(p.Body)
  buffer.Write(padding[:])

  return buffer.Bytes(), nil
}

func NewPacket(id, typ int32, body string) (packet *Packet) {
  size := int32(len([]byte(body)) + 10)
  return &Packet{Header{size, id, typ}, body}
}

func (c *Client) Authorize(password string) (response *Packet, err error) {
  if response, err = c.Execute(3, password); nil == err {
    c.Authorized = true
  }

  return
}

func (c *Client) Execute(typ int32, command string) (response *Packet, err error) {
  c.ChallengeIndex += 1

  packet := NewPacket(int32(c.ChallengeIndex), typ, command)
  payload, err := packet.Compile()

  var n int

  if nil != err {
    return
  } else if n, err = c.Connection.Write(payload); nil != err {
    err = ErrInvalidWrite
    return
  }

  var header Header

  if err = binary.Read(c.Connection, binary.LittleEndian, &header.Size); nil != err {
    return
  } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.Challenge); nil != err {
    return
  } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.Type); nil != err {
    return
  }

  if packet.Header.Type == 3 && header.Type == 0 {
    // Discard, empty SERVERDATA_RESPONSE_VALUE from authorization.
    c.Connection.Read(make([]byte, header.Size-PACKET_HEADER_SIZE))

    // Reread the packet header.
    if err = binary.Read(c.Connection, binary.LittleEndian, &header.Size); nil != err {
      return
    } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.Challenge); nil != err {
      return
    } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.Type); nil != err {
      return
    }
  }

  if header.Challenge != packet.Header.Challenge {
    err = ErrInvalidChallenge
    return
  }

  body := make([]byte, header.Size-PACKET_HEADER_SIZE)

  n, err = c.Connection.Read(body)

  if nil != err {
    return
  } else if n != len(body) {
    err = ErrInvalidRead
    return
  }

  response = new(Packet)
  response.Header = header
  response.Body = strings.TrimRight(string(body), "\x00")

  return
}

func NewClient(host string, port int) (client *Client, err error) {
  client = new(Client)
  client.Host = host
  client.Port = port
  client.ChallengeIndex = 0
  client.Connection, err = net.Dial("tcp", fmt.Sprintf("%v:%v", client.Host, client.Port))
  return
}
