import argparse
import os

def main():
    prsr = argparse.ArgumentParser("debug output splitter")

    prsr.add_argument("target_file", type=argparse.FileType('r'))
    prsr.add_argument("output_path")

    args = prsr.parse_args()

    target_lines = set(["pred:", "prev_val:","nval:", "last_pred:"])

    for line in reversed(args.target_file.readlines()):
        line = str(line)
        for tline in list(target_lines):
            if line.find(tline) != -1:
                target_lines.remove(tline)
                res = line.replace("->", "->\n")
                with open(os.path.join(args.output_path, tline), "w") as f:
                    f.write(res)


if __name__ == "__main__":
    main()