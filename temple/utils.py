import pwn
import jinja2

def format(template_file, args={}):
    template = jinja2.Template(open(template_file, 'r').read())
    return template.render(**args)

def find_overflow(binary):
    p = pwn.process(binary)
    p.sendline(pwn.cyclic(10000))
    p.recv(1)
    p.close()

    assert p.returncode != -11, "Did not crash"

    core = pwn.Coredump("./core")
    return pwn.cyclic_find(pwn.pack(core.eip))
