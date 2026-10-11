"""Architecture diagrams and directory trees in the docs name files that exist and stay well formed."""
import re
import subprocess
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ["README.md", "docs/ARCHITECTURE.md"]
ARROW = re.compile(r"\s*(?:<-->|<-\.->|-\.->|-->|==>|---)\s*")
SHAPE = re.compile(r"^([A-Za-z_][\w]*)\s*(?:\(\[|\[\(|\(\(|\[\[|\[|\(|\{)")
FILE_NAME = re.compile(r"[\w./-]*\w\.(?:py|tsx?|mjs|ya?ml|json|md|sha256|txt)\b")


def tracked():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    # git names paths with "/" on every platform; Windows' Path would rebuild them with "\\".
    dirs = {str(PurePosixPath(name).parents[i]) for name in files for i in range(len(PurePosixPath(name).parts) - 1)}
    return set(files), dirs


FILES, DIRS = tracked()
BASENAMES = {Path(name).name for name in FILES}


def halves(name):
    text = (ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n")
    chinese, english = re.split(r"^---$", text, maxsplit=1, flags=re.M)
    return chinese, english


def blocks(text, language):
    return re.findall(rf"^```{language}\n(.*?)^```", text, flags=re.S | re.M)


def mermaid_graph(block):
    """Node IDs, edges and subgraph IDs of a flowchart, with every label removed."""
    nodes, edges, subgraphs, depth = set(), set(), set(), 0
    for raw in block.split("\n")[1:]:
        line = re.sub(r'"[^"]*"', "", raw).strip()
        line = re.sub(r"\|[^|]*\|", "", line)
        if not line or line.startswith("%%") or line.startswith("direction "):
            continue
        if line.startswith("subgraph "):
            depth += 1
            subgraphs.add(re.match(r"subgraph\s+(\w+)", line).group(1))
            continue
        if line == "end":
            depth -= 1
            assert depth >= 0, "an 'end' without a subgraph"
            continue
        parts = ARROW.split(line)
        ids = []
        for part in parts:
            group = []
            for item in part.split("&"):
                item = item.strip()
                match = SHAPE.match(item)
                if match:
                    nodes.add(match.group(1))
                    group.append(match.group(1))
                elif item:
                    assert re.fullmatch(r"[A-Za-z_]\w*", item), f"cannot read node reference {item!r} in: {raw.strip()}"
                    group.append(item)
            ids.append(group)
        for left, right in zip(ids, ids[1:]):
            edges.update((a, b) for a in left for b in right)
    assert depth == 0, "subgraph without 'end'"
    return nodes, edges, subgraphs


def diagrams():
    for name in DOCS:
        chinese, english = halves(name)
        zh, en = blocks(chinese, "mermaid"), blocks(english, "mermaid")
        assert len(zh) == len(en), f"{name}: the halves have a different number of diagrams"
        for i, (a, b) in enumerate(zip(zh, en)):
            yield pytest.param(name, a, b, id=f"{name}#{i}")


@pytest.mark.parametrize("name,chinese,english", list(diagrams()))
def test_diagrams_are_well_formed_and_the_same_in_both_languages(name, chinese, english):
    zh_nodes, zh_edges, zh_groups = mermaid_graph(chinese)
    en_nodes, en_edges, en_groups = mermaid_graph(english)
    known = zh_nodes | zh_groups
    used = {node for edge in zh_edges for node in edge}
    assert used <= known, f"{name}: edges use undefined nodes {sorted(used - known)}"
    assert zh_nodes <= used | zh_groups, f"{name}: nodes with no edge {sorted(zh_nodes - used)}"
    assert (zh_nodes, zh_edges, zh_groups) == (en_nodes, en_edges, en_groups), f"{name}: the Chinese and English diagrams differ"


def labelled_files(text):
    for block in blocks(text, "mermaid"):
        yield from FILE_NAME.findall(block)
    for code in re.findall(r"`([^`\n]+)`", re.sub(r"^```.*?^```", "", text, flags=re.S | re.M)):
        if re.fullmatch(FILE_NAME.pattern, code):
            yield code


@pytest.mark.parametrize("name", DOCS)
def test_files_named_in_architecture_docs_exist(name):
    missing = sorted({ref for half in halves(name) for ref in labelled_files(half)
                      if ref not in FILES and Path(ref).name not in BASENAMES})
    assert not missing, f"{name} names files that are not in the repository: {missing}"


def tree_paths(block):
    """Paths listed in a ├──/└── directory tree, rebuilt from the indentation."""
    parents, paths = {}, []
    for line in block.split("\n")[1:]:
        match = re.match(r"^((?:│   |    )*)(?:├── |└── )(.+)$", line)
        if not match:
            continue
        depth = len(match.group(1)) // 4
        entry = re.split(r"\s{2,}#|\s#\s", match.group(2))[0].strip()
        for item in re.split(r" / | · ", entry):
            path = parents.get(depth - 1, "") + item
            paths.append(path)
            if item.endswith("/"):
                parents[depth] = path
    return paths


@pytest.mark.parametrize("half", [0, 1], ids=["chinese", "english"])
def test_readme_directory_tree_matches_the_repository(half):
    text = halves("README.md")[half]
    (tree,) = [block for block in blocks(text, "text") if block.startswith("MultiAgentBeta/")]
    paths = tree_paths(tree)
    missing = [path for path in paths if path.rstrip("/") not in FILES | DIRS]
    assert not missing, f"README tree lists paths that do not exist: {missing}"
    listed = set(paths)
    modules = sorted(name for name in FILES if re.fullmatch(r"backend/vibe_audit/\w+\.py", name) and name not in listed and not name.endswith("__init__.py"))
    assert not modules, f"README tree omits backend modules: {modules}"
    tests = [name for name in FILES if re.fullmatch(r"tests/test_\w+\.py", name)]
    stated = re.search(r"pytest\s*[（(](\d+)", tree)
    assert stated and int(stated.group(1)) == len(tests), f"README tree states {stated and stated.group(1)} test files; there are {len(tests)}"
