import argparse
import importlib
import sys
import os

def import_file(filename):
    path = sys.path
    try:
        filename = os.path.abspath(filename)
        sys.path.insert(0, os.path.dirname(filename))

        module = os.path.splitext(os.path.basename(filename))[0]
        return importlib.import_module(module)
    finally:
        sys.path = path

def load_attack_definition(filename):
    attackdef = import_file(filename)

    hooks = {}
    try: hooks['setup'] = attackdef.setup
    except: pass

    try: hooks['teardown'] = attackdef.teardown
    except: pass

    menus = attackdef.interaction

    return {
        'binary': attackdef.binary,
        'hooks':  hooks,
        'menus':  attackdef.interaction,
        '__mod':  attackdef
    }

def std_cli(load=True):
    parser = argparse.ArgumentParser()
    parser.add_argument('attack_definition')
    argp = parser.parse_args()

    if load:
        return load_attack_definition(argp.attack_definition)
    else:
        return argp
