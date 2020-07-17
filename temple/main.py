import modules.rop
import utils
import sys

def split_args(argv):
    a1 = []
    a2 = []
    buf = a1
    for arg in argv:
        if arg == '--':
            buf = a2
            continue
        buf.append(arg)
    return a1, a2

def cli(argv):
    cli_args, mod_args = split_args(argv)

    method = cli_args[0]
    outfile = cli_args[1]

    if method == 'rop':
        mod = modules.rop.RopTemplater()
    else:
        raise ValueError(f"Unknown module {method}")

    mod.parse_args(mod_args)
    return mod, outfile

def get_template(templater):
    return utils.format(
        templater.template,
        templater.template_args()
    )

if __name__ == '__main__':
    mod, outfile = cli(sys.argv[1:])
    template = get_template(mod) 
    with open(outfile, 'w') as w:
        w.write(template)
