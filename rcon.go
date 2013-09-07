// Package rcon implements the communication protocol for communicating
// with RCON servers. Tested and working with Valve game servers.
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

type CommandType int32

const (
  EXEC_COMMAND CommandType = 2
  AUTH         CommandType = 3
)

type ResponseType int32

const (
  AUTH_RESPONSE  ResponseType = 2
  RESPONSE_VALUE ResponseType = 0
)

var (
  ErrInvalidWrite        = errors.New("Failed to write the payload corretly to remote connection.")
  ErrInvalidRead         = errors.New("Failed to read the response corretly from remote connection.")
  ErrInvalidChallenge    = errors.New("Server failed to mirror request challenge.")
  ErrUnauthorizedRequest = errors.New("Client not authorized to remote server.")
  ErrFailedAuthorization = errors.New("Failed to authorize to the remote server.")
)

type Client struct {
  Host           string   // The IP address of the remote server.
  Port           int      // The Port the remote server's listening on.
  ChallengeIndex int      // The current ChallengeIndex used to ensure server mirrors correctly.
  Authorized     bool     // Has the client been authorized by the server?
  Connection     net.Conn // The TCP connection to the server.
}

type Header struct {
  Size      int32 // The size of the payload.
  Challenge int32 // The challenge ths server should mirror.
  Type      int32 // The type of request being sent.
}

type Packet struct {
  Header Header // Packet header.
  Body   string // Body of packet.
}

// Compile converts a packets header and body into its approriate
// byte array payload, returning an error if the binary packages
// Write method fails to write the header bytes in their little
// endian byte order.
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

// NewPacket returns a pointer to a new Packet type.
func NewPacket(challenge, typ int32, body string) (packet *Packet) {
  size := int32(len([]byte(body)) + 10)
  return &Packet{Header{size, challenge, typ}, body}
}

// Authorize calls Execute with the appropriate CommandType and the provided
// password.  The response packet is returned if authorization is successful,
// or a potential error.
func (c *Client) Authorize(password string) (response *Packet, err error) {
  if response, err = c.Execute(AUTH, password); nil == err {
    if response.Header.Type == AUTH_RESPONSE {
      c.Authorized = true
    } else {
      err = ErrFailedAuthorization
      response = nil
      return
    }
  }

  return
}

// Execute sends the command to execute to the clients server, decompiling
// the response's bytes into a Packet type for return.  An error is returned
// if Execute fails.
func (c *Client) Execute(typ int32, command string) (response *Packet, err error) {
  if typ != AUTH && !c.Authorized {
    err = ErrUnauthorizedRequest
    return
  }

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

  if packet.Header.Type == AUTH && header.Type == RESPONSE_VALUE {
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

// NewClient creates a new Client type, creating the connection
// to the server specified by the host and port arguements. If
// the connection fails, an error is returned.
func NewClient(host string, port int) (client *Client, err error) {
  client = new(Client)
  client.Host = host
  client.Port = port
  client.ChallengeIndex = 0
  client.Connection, err = net.Dial("tcp", fmt.Sprintf("%v:%v", client.Host, client.Port))
  return
}
