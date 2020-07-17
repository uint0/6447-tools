def menu(p, o):
    content = p.recvuntil('sh):')
    p.sendline(o)
    return content

def overflow(payload, p):
    menued = menu(p, 'O')
    return menued + p.recvline() + p.recvline()

def underflow(payload, p):
    menued = menu(p, 'U')
    prompt = p.recvuntil(':')
    p.sendline(payload[:248])
    return menued + prompt + p.recvuntil('[O]')

def printflag(payload, p):
    menued = menu(p, 'P')
    p.sendline('')
    return menued + p.recvuntil('[O]')

interaction = {
    'overflow': overflow,
    'underflow': underflow,
    'printflag': printflag
}

binary = '../bins/ezpz'
