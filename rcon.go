// Package rcon implements the communication protocol for communicating
// with RCON servers. Tested and working with Valve game servers.
package rcon

import (
  "bytes"
  "crypto/rand"
  "encoding/binary"
  "errors"
  "fmt"
  "net"
  "strings"
)

const (
  PACKET_PADDING_SIZE = 2 // Size of Packet's padding.
  PACKET_HEADER_SIZE  = 8 // Size of Packet's header.
)

const (
  TERMINATION_SEQUENCE = "\x00" // Null empty ASCII string suffix.
)

// Packet type constants.
// https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Packet_Type
const (
  EXEC_COMMAND   int32 = 2
  AUTH           int32 = 3
  AUTH_RESPONSE  int32 = 2
  RESPONSE_VALUE int32 = 0
)

// Rcon package errors.
var (
  ErrInvalidWrite        = errors.New("Failed to write the payload corretly to remote connection.")
  ErrInvalidRead         = errors.New("Failed to read the response corretly from remote connection.")
  ErrInvalidChallenge    = errors.New("Server failed to mirror request challenge.")
  ErrUnauthorizedRequest = errors.New("Client not authorized to remote server.")
  ErrFailedAuthorization = errors.New("Failed to authorize to the remote server.")
)

type Client struct {
  host       string   // The IP address of the remote server.
  port       int      // The Port the remote server's listening on.
  authorized bool     // Has the client been authorized by the server?
  connection net.Conn // The TCP connection to the server.
}

type Header struct {
  size      int32 // The size of the payload.
  challenge int32 // The challenge ths server should mirror.
  typ       int32 // The type of request being sent.
}

type Packet struct {
  header Header // Packet header.
  Body   string // Body of packet.
}

// Compile converts a packets header and body into its approriate
// byte array payload, returning an error if the binary packages
// Write method fails to write the header bytes in their little
// endian byte order.
func (p Packet) Compile() (payload []byte, err error) {
  var size int32 = p.header.size
  var buffer bytes.Buffer
  var padding [PACKET_PADDING_SIZE]byte

  if err = binary.Write(&buffer, binary.LittleEndian, &size); nil != err {
    return
  } else if err = binary.Write(&buffer, binary.LittleEndian, &p.header.challenge); nil != err {
    return
  } else if err = binary.Write(&buffer, binary.LittleEndian, &p.header.typ); nil != err {
    return
  }

  buffer.WriteString(p.body)
  buffer.Write(padding[:])

  return buffer.Bytes(), nil
}

// NewPacket returns a pointer to a new Packet type.
func NewPacket(challenge, typ int32, body string) (packet *Packet) {
  size := int32(len([]byte(body)) + PACKET_HEADER_SIZE + PACKET_PADDING_SIZE)
  return &Packet{Header{size, challenge, typ}, body}
}

// Authorize calls Send with the appropriate command type and the provided
// password.  The response packet is returned if authorization is successful
// or a potential error.
func (c *Client) Authorize(password string) (response *Packet, err error) {
  if response, err = c.send(AUTH, password); nil == err {
    if response.header.typ == AUTH_RESPONSE {
      c.Authorized = true
    } else {
      err = ErrFailedAuthorization
      response = nil
      return
    }
  }

  return
}

// Execute calls Send with the appropriate command type and the provided
// command.  The response packet is returned if the command executed successfully
// or a potential error.
func (c *Client) Execute(command string) (response *Packet, err error) {
  return c.send(EXEC_COMMAND, command)
}

// Send accepts the commands type and its string to execute to the clients server,
// creating a packet with a random challenge id for the server to mirror,
// and compiling its payload bytes in the appropriate order. The resonse is
// decompiled from its bytes into a Packet type for return. An error is returned
// if send fails.
func (c *Client) Send(typ int32, command string) (response *Packet, err error) {
  if typ != AUTH && !c.Authorized {
    err = ErrUnauthorizedRequest
    return
  }

  // Create a random challenge for the server to mirror in its response.
  var challenge int32
  binary.Read(rand.Reader, binary.LittleEndian, &challenge)

  // Create the packet from the challenge, typ and command
  // and compile it to its byte payload
  packet := NewPacket(challenge, typ, command)
  payload, err := packet.Compile()

  var n int

  if nil != err {
    return
  } else if n, err = c.connection.Write(payload); nil != err {
    return
  } else if n != len(payload) {
    err = ErrInvalidWrite
    return
  }

  var header Header

  if err = binary.Read(c.connection, binary.LittleEndian, &header.size); nil != err {
    return
  } else if err = binary.Read(c.connection, binary.LittleEndian, &header.challenge); nil != err {
    return
  } else if err = binary.Read(c.connection, binary.LittleEndian, &header.typ); nil != err {
    return
  }

  if packet.header.typ == AUTH && header.typ == RESPONSE_VALUE {
    // Discard, empty SERVERDATA_RESPONSE_VALUE from authorization.
    c.connection.Read(make([]byte, header.size-PACKET_HEADER_SIZE))

    // Reread the packet header.
    if err = binary.Read(c.connection, binary.LittleEndian, &header.size); nil != err {
      return
    } else if err = binary.Read(c.connection, binary.LittleEndian, &header.challenge); nil != err {
      return
    } else if err = binary.Read(c.connection, binary.LittleEndian, &header.typ); nil != err {
      return
    }
  }

  if header.challenge != packet.header.challenge {
    err = ErrInvalidChallenge
    return
  }

  body := make([]byte, header.size-PACKET_HEADER_SIZE)

  n, err = c.connection.Read(body)

  if nil != err {
    return
  } else if n != len(body) {
    err = ErrInvalidRead
    return
  }

  response = new(Packet)
  response.header = header
  response.body = strings.TrimRight(string(body), TERMINATION_SEQUENCE)

  return
}

// NewClient creates a new Client type, creating the connection
// to the server specified by the host and port arguements. If
// the connection fails, an error is returned.
func NewClient(host string, port int) (client *Client, err error) {
  client = new(Client)
  client.host = host
  client.port = port
  client.connection, err = net.Dial("tcp", fmt.Sprintf("%v:%v", client.host, client.port))
  return
}
