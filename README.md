# rcon

Package `rcon` implements the communication protocol for communicating with RCON servers. Tested and working with Valve game servers.

## Installation

With Google's [Go](http://www.golang.org) installed on your machine:

    $ go get -u github.com/chuckpreslar/rcon

## Usage

A simple example using the library to authorize to the RCON server and issue a command.

```go
package main

import (
  "github.com/chuckpreslar/rcon"
)

func main() {
  client, err := rcon.NewClient("127.0.0.1" /* Your servers IP address */, 27015 /* Its port */)
  
  if nil != err {
    // Failed to open TCP connection to server.
    panic(err)
  }
  
  var packet *rcon.Packet
  
  packet, err = client.Authorize("password" /* The RCON password for your server */)
  
  if nil != err {
    // Failed to authorize your connection with the server.
    panic(err)
  }
  
  packet, err = client.Execute(rcon.EXECCOMMAND /* Type of command to execute */, "command" /* The command to run */)
  
  if nil != err {
    // Failed to execute command
    panic(err)
  }
  
  // Result of running command stored in packet.Body
  
}
```
    
## Documentation

View godoc or visit [godoc.org](http://godoc.org/github.com/chuckpreslar/rcon).

    $ godoc rcon

## License

> The MIT License (MIT)

> Copyright (c) 2013 Chuck Preslar

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:

> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
> THE SOFTWARE.
