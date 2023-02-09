import graphviz
import json
import argparse


def main():
    prsr = argparse.ArgumentParser()
    prsr.add_argument("target_json")
    prsr.add_argument("out_dot")

    args = prsr.parse_args()

    with open(args.target_json, "r") as f:
        patch_specs = json.load(f)

    digraph = graphviz.Digraph("Patches")

    for nd in patch_specs["patches"]:
        digraph.node(nd["patch-addr"],
                     nd["patch-code"].replace("\n", "\l"), shape="rectangle")

        for e in nd["edges"]:
            digraph.edge(nd["patch-addr"], e)

    print(digraph)


if __name__ == "__main__":
    main()
