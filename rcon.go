package rcon

import (
  "bytes"
  "encoding/binary"
  "fmt"
)

type Client struct {
  host string
  port int
}

type Header struct {
  size int32
  id   int32
  typ  int32
}

type Packet struct {
  header Header
  body   string
}

func (p Packet) Compile() (b []byte, e error) {
  var buffer bytes.Buffer
  e = binary.Write(&buffer, binary.LittleEndian, &p.header)

  if nil != e {
    return
  }

  buffer.Write([]byte(p.body))
  return buffer.Bytes(), nil
}

func NewPacket(id, typ int32, body string) (packet *Packet) {
  content := []byte(body)
  size := int32(len(content) + 14)
  return &Packet{Header{size - 4, id, typ}, content}
}

func (c *Client) Authorize(password string) *Client {
  return c
}

func NewClient(host string, port int) *Client {
  return &Client{host, port}
}
