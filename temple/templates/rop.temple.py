import pwn

BINARY = "{{ binary }}"
REMOTE = ("{{ remote_host }}", {{ remote_port }})

if pwn.args['REMOTE']:
    p = pwn.remote(REMOTE[0], REMOTE[1])
    elf = pwn.ELF(BINARY)
    {% if libc is not none %}libc = pwn.ELF("{{ libc['REMOTE'] }}"){% endif %}
else:
    p = pwn.process(BINARY)
    elf = p.elf
    {% if libc is not none %}libc = pwn.ELF("{{ libc['LOCAL'] }}"){% endif %}

def ropchain(chain, save=None):
    def flatten(arr):
        s = []
        for e in arr:
            if isinstance(e, list):
                s += flatten(e)
            else:
                if isinstance(e, int):
                    e = pwn.p32(e)
                s.append(e)
        return s

    rop = b''.join(flatten(chain))

    if save is not None:
        with open(save, 'wb') as w:
            w.write(rop + b'\n')

    return rop

payload = ropchain([
    b'A'*{{ overflow - 4 }},
    b'$ebp',

    # YOUR ROP CHAIN HERRE
], save=f"{BINARY}.payload")

p.sendline(payload)
p.interactive()
