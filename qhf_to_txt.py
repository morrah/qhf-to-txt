import struct
import datetime
import argparse


def main(infile, outfile):
    with open(infile, 'rb') as f:
        txt = qhf_to_txt(f)

    if outfile:
        with open(outfile, 'w') as f:
            f.write(txt)
    else:
        print(txt)


def qhf_to_txt(f):
    struct_header = '>3sBI36sH'
    buf = f.read(3 + 1 + 4 + 36 + 2)
    (
        magicbytes,
        version,
        fsz,
        _,
        UIDLen,
    ) = struct.unpack(struct_header, buf)

    buf = f.read(UIDLen + 2)
    (
        UIDStr,
        NickLen,
    ) = struct.unpack(f'>{UIDLen}sH', buf)

    buf = f.read(NickLen)
    (
        NickStr,
    ) = struct.unpack(f'>{NickLen}s', buf)

    username = NickStr.decode('utf8')

    if version >= 3:
        msg_header_size = 0x23
    else:
        msg_header_size = 0x21

    history_log = []
    while (msg_header := f.read(msg_header_size)):
        msg_size = struct.unpack('>I', msg_header[-4:])[0]
        msg_timestamp = struct.unpack('>I', msg_header[18:22])[0]
        is_outgoing = msg_header[26]

        msg = f.read(msg_size)
        # messages are encrypted with xor with increment
        decoded_msg = bytes(
            map(
                lambda val, pos: (val + pos) & 0xFF ^ 0xFF,
                msg,
                range(1, len(msg)+1),
            )
        ).decode('utf8')

        formatted_msg = format_log(
            'Me' if is_outgoing else username,
            datetime.datetime.fromtimestamp(msg_timestamp),
            decoded_msg,
        )

        history_log.append(formatted_msg)
    return '\n\n'.join(history_log)


def format_log(name, timestamp, message):
    return '\n'.join([
        name + ' [' + str(timestamp) + ']',
        message,
    ])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='qhf_to_txt.py',
        description='reads binary QHF (qip history file)',
    )
    parser.add_argument('infile', type=str,
                        help='input history file')
    parser.add_argument('outfile', type=str, nargs='?',
                        help='output text file; if omitted, outputs to stdout')
    args = parser.parse_args()
    main(args.infile, args.outfile)
