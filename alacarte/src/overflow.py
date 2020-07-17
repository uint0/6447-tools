import pwn

PAYLOAD = pwn.cyclic(1024)

def find_buffer_size(binary, route, menus, hooks={}, core_finder=lambda: './core'):
    binary = pwn.process(binary)

    if 'setup' in hooks: hooks['setup'](binary)

    try:
        for item in route:
            menus[item](PAYLOAD, binary)
    except EOFError:
        pass
    else:
        assert False, "Did not crash"

    binary.close()
    assert binary.returncode == -11, "Did not Segmentation Fault (SIGSEGV = -11)"

    core = pwn.Coredump(core_finder())
    offset = pwn.cyclic_find(pwn.pack(core.eip))

    return offset


if __name__ == '__main__':
    import argparse
    import utils

    parser = argparse.ArgumentParser()
    parser.add_argument('attack_definition')
    parser.add_argument('crash_route')
    argp = parser.parse_args()

    attack_definition = utils.load_attack_definition(argp.attack_definition)
    bufsiz = find_buffer_size(attack_definition['binary'], argp.crash_route.split(','), attack_definition['menus'], attack_definition['hooks'])
    print(f'Crashed on offset: 0x{bufsiz:x} = {bufsiz}')
