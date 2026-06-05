import random


def build_graph(random_pages=30, links_per_page=4, seed=1337):
    random.seed(seed)
    graph = {}

    # Circular network
    circle_nodes = ["A", "B", "C", "D", "E"]
    for idx, node in enumerate(circle_nodes):
        nxt = circle_nodes[(idx + 1) % len(circle_nodes)]
        graph[f"/reseau/circulaire/{node}"] = [f"/reseau/circulaire/{nxt}"]

    # Tree network
    graph["/reseau/arbre/root"] = [
        "/reseau/arbre/1",
        "/reseau/arbre/2",
        "/reseau/arbre/3",
    ]
    graph["/reseau/arbre/1"] = ["/reseau/arbre/1a", "/reseau/arbre/1b"]
    graph["/reseau/arbre/1a"] = []
    graph["/reseau/arbre/1b"] = []
    graph["/reseau/arbre/2"] = []
    graph["/reseau/arbre/3"] = []

    # Deep network (1 -> 2 -> ... -> 100)
    for i in range(1, 101):
        current = f"/reseau/profondeur/{i}"
        nxt = f"/reseau/profondeur/{i + 1}" if i < 100 else "/reseau/profondeur/1"
        graph[current] = [nxt]

    # Random network
    random_nodes = [f"/reseau/aleatoire/{i}" for i in range(1, random_pages + 1)]
    for node in random_nodes:
        targets = set()
        while len(targets) < min(links_per_page, len(random_nodes)):
            targets.add(random.choice(random_nodes))
        graph[node] = sorted(targets)

    # Cross-links to test strategy changes
    graph["/"] = [
        "/reseau/circulaire/A",
        "/reseau/arbre/root",
        "/reseau/profondeur/1",
        "/reseau/aleatoire/1",
        "/cap/tests",
    ]

    return graph


def page_title_from_path(path):
    return f"Page test {path}".replace("/", " ").strip()
