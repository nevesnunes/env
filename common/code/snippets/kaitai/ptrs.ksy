meta:
  id: ptrs
  endian: le
seq:
  - id: header_field1
    type: u2
  - id: header_field2
    type: u2
  - id: header_field3_u8x4
    type: body_u8
    repeat: expr
    repeat-expr: 4
types:
  body_u8:
    seq:
      - id: u8
        type: u1
  body_u16:
    seq:
      - id: u16
        type: u2
  body_u16ptr16:
    seq:
      - id: u16
        type: u2
      - id: ptr16
        type: u2
    instances:
      ref_header_field2_ptr:
        io: _root.ref_header_field2._io
        pos: ptr16
        type: body_u16
instances:
  ref_header_field2:
    pos: header_field2
    type: body_u16ptr16
  footer:
    pos: _io.size - 2
    type: u2
