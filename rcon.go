package rcon

import (
  "bytes"
  "encoding/binary"
  "errors"
  "fmt"
  "net"
)

const (
  PACKET_PADDING = 2
)

var (
  ErrInvalidWrite = errors.New("Failed to write the payload corretly to remote connection.")
  ErrInvalidRead  = errors.New("Failed to read the response corretly from remote connection.")
)

type Client struct {
  Host         string
  Port         int
  CommandsSent int
  Authorized   bool
  Connection   net.Conn
}

type Header struct {
  Size int32
  ID   int32
  Type int32
}

type Packet struct {
  Header Header
  Body   string
}

func (p Packet) Compile() (payload []byte, err error) {
  var size int32 = p.Header.Size - 4
  var buffer bytes.Buffer
  var padding [PACKET_PADDING]byte

  if err = binary.Write(&buffer, binary.LittleEndian, &size); nil != err {
    return
  } else if err = binary.Write(&buffer, binary.LittleEndian, &p.Header.ID); nil != err {
    return
  } else if err = binary.Write(&buffer, binary.LittleEndian, &p.Header.Type); nil != err {
    return
  }

  buffer.WriteString(p.Body)
  buffer.Write(padding[:])

  return buffer.Bytes(), nil
}

func DecompileResponse(response []byte) Packet {
  return Packet{}
}

func NewPacket(id, typ int32, body string) (packet *Packet) {
  size := int32(len([]byte(body)) + 14)
  return &Packet{Header{size, id, typ}, body}
}

func (c *Client) Authorize(password string) (response *Packet, err error) {
  if response, err = c.Execute(3, password); nil == err {
    c.Authorized = true
  }

  return
}

func (c *Client) Execute(typ int32, command string) (response *Packet, err error) {
  c.CommandsSent += 1

  packet := NewPacket(int32(c.CommandsSent), typ, command)
  payload, err := packet.Compile()

  var read int

  if nil != err {
    return
  } else if read, err = c.Connection.Write(payload); nil != err {
    err = ErrInvalidWrite
    return
  }
  // var header Header
  var header Header

  if err = binary.Read(c.Connection, binary.LittleEndian, &header.Size); nil != err {
    return
  } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.ID); nil != err {
    return
  } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.Type); nil != err {
    return
  }

  if packet.Header.Type == 3 && header.Type == 0 {
    // Discard, empty SERVERDATA_RESPONSE_VALUE from authorization.
    c.Connection.Read(make([]byte, header.Size+PACKET_PADDING))

    // Reread the packet header.
    if err = binary.Read(c.Connection, binary.LittleEndian, &header.Size); nil != err {
      return
    } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.ID); nil != err {
      return
    } else if err = binary.Read(c.Connection, binary.LittleEndian, &header.Type); nil != err {
      return
    }
  }

  body := make([]byte, header.Size+PACKET_PADDING)

  read, err = c.Connection.Read(body)

  if nil != err {
    return
  }

  response = new(Packet)
  response.Header = header
  response.Body = string(body)

  return
}

func NewClient(host string, port int) (client *Client, err error) {
  client = new(Client)
  client.Host = host
  client.Port = port
  client.CommandsSent = 0
  client.Connection, err = net.Dial("tcp", fmt.Sprintf("%v:%v", client.Host, client.Port))
  return
}
