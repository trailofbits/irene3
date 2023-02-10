import graphviz
import json
import argparse
import sys


def main():
    prsr = argparse.ArgumentParser()
    prsr.add_argument("target_json", type=argparse.FileType('r'))
    prsr.add_argument("out_dot", nargs="?", type=argparse.FileType('w'), default=sys.stdout)

    args = prsr.parse_args()

    patch_specs = json.load(args.target_json)

    digraph = graphviz.Digraph("Patches")

    for nd in patch_specs["patches"]:
        digraph.node(nd["patch-addr"],
                     nd["patch-code"].replace("\n", r"\l"), shape="rectangle")

        for e in nd["edges"]:
            digraph.edge(nd["patch-addr"], e)

    args.out_dot.write(str(digraph))


if __name__ == "__main__":
    main()
