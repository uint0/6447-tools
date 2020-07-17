import pwn
import itertools
import re

PAYLOAD = '%p' * 1000

def is_suspicious(res):
    return len(re.findall(r"(0x[0-9]{8}|\(nil\))", res.decode())) > 4

def get_execution_plan(menus, size=5):
    """
    Build out a series of steps to check.
    E.g. For a menu structure of
    {
        menu1: {menu1.1: {menu1.1.1: FN, menu1.1.2: FN}, menu1.2: FN},
        menu2: {menu2.1: {menu2.1.1: FN}, menu2.2: FN},
        menu3: {menu3.1: FN},
        menu4: FN
    }

    We would like to produce a execution plan similar to

    [ [ menu1[menu1.1][menu1.1.1] ], [ menu1[menu1.1][menu1.1.2] ], ...,

      [ menu1[menu1.1][menu1.1.1], menu1[menu1.1][menu1.1.1] ],
      [ menu1[menu1.1][menu1.1.1], menu1[menu1.1][menu1.1.2] ], ...]

    The execution plan would have SUM[i=1..size](NUM_LEAFS(menu) ** i) series
    """

    # 1. Extract a list of leaf nodes using a {path_name: FN} association
    def dfs(root, prefix=''):
        for name, submenu in root.items():
            name = f"{prefix}/{name}"
            if callable(submenu):
                yield (name, submenu)
            else:
                yield from dfs(submenu, name)

    leaves = {}
    for name, fn in dfs(menus):
        leaves[name] = fn

    # 2. Generate a set of key products
    job_list = []
    for i in range(1, size+1):
        job_list += itertools.product(leaves.keys(), repeat=i)

    # Return the leaves list and job list
    return leaves, job_list

def search(binary, interactors, execution_plan, hooks={}):
    for series in execution_plan:
        p = pwn.process(binary)
        if 'setup' in hooks:
            hooks['setup'](p)

        buffer = []
        for i, step in enumerate(series):
            try:
                result = interactors[step](PAYLOAD, p)
                buffer.append(result)
                sus = is_suspicious(result)
            except EOFError:
                sus = True
                buffer.append('<<<EOF>>>')
            if sus:
                yield (series, buffer, i)
                break

        if 'teardown' in hooks:
            hooks['teardown'](p)

        p.close()

def run(binary, menus, hooks={}, size=3):
    interactors, executions = get_execution_plan(menus, size=size)
    for result in search(binary, interactors, executions, hooks=hooks):
        print(result)
        break

if __name__ == '__main__':
    import utils
    attackdef = utils.std_cli()
    run(attackdef['binary'], attackdef['menus'], size=3, hooks=attackdef['hooks'])

