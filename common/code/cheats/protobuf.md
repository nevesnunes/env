```protobuf
syntax = "proto3";

message Greeting {
    string status = 1; 
    string message = 2;
}
```

```bash
protoc --js_out=import_style=commonjs,binary:. \
    greeting.proto
```

```javascript
var pb = require('./greeting_pb')

// Serialization
var data = { status: 'OK', message: 'Hello JSON!' }
var msg = new pb.Greeting();
msg.setStatus(data.status)
msg.setMessage(data.message)
var bytes = msg.serializeBinary();

// Deserialization
var msg2 = pb.Greeting.deserializeBinary(bytes)
console.log(msg2.getStatus(), msg2.getMessage())

// 10 2 79 75 18 11 72 101 108 108 111 32 74 83 79 78 33
//      O  K        H   e   l   l   o     J  S  O  N  !
```

https://codeburst.io/protocol-buffers-part-3-json-format-e1ca0af27774


