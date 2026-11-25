"""Clearly labelled demonstration Random Forest for blood shortage risk.

The repository has no labelled blood-group shortage history. This model is
trained only on deterministic synthetic scenarios and must not be used for
clinical or allocation decisions.
"""
import random


MODE = "DEMONSTRATION MODE (synthetic training examples; not operational)"


def _label(stock, demand):
    coverage = stock / max(demand, 1)
    if (demand and coverage < 1) or (not demand and stock <= 2):
        return "High"
    if (demand and coverage < 2) or (not demand and stock <= 8):
        return "Medium"
    return "Low"


def _gini(labels):
    n = len(labels)
    if not n:
        return 0
    return 1 - sum((labels.count(label) / n) ** 2 for label in set(labels))


def _fit_tree(rows, rng, depth=0):
    labels = [row[2] for row in rows]
    majority = max(set(labels), key=labels.count)
    if depth >= 4 or len(set(labels)) == 1 or len(rows) < 4:
        return ("leaf", majority)
    feature = rng.randrange(2)
    values = sorted(set(row[feature] for row in rows))
    if len(values) < 2:
        feature = 1 - feature
        values = sorted(set(row[feature] for row in rows))
    if len(values) < 2:
        return ("leaf", majority)
    candidates = [((a + b) / 2) for a, b in zip(values, values[1:])]
    rng.shuffle(candidates)
    best = None
    for threshold in candidates[:min(12, len(candidates))]:
        left = [r for r in rows if r[feature] <= threshold]
        right = [r for r in rows if r[feature] > threshold]
        score = (len(left) * _gini([r[2] for r in left]) +
                 len(right) * _gini([r[2] for r in right])) / len(rows)
        if best is None or score < best[0]:
            best = (score, feature, threshold, left, right)
    if best is None or best[0] >= _gini(labels):
        return ("leaf", majority)
    _, feature, threshold, left, right = best
    return ("node", feature, threshold, _fit_tree(left, rng, depth + 1),
            _fit_tree(right, rng, depth + 1), majority)


def _tree_predict(tree, features):
    if tree[0] == "leaf":
        return tree[1]
    _, feature, threshold, left, right, fallback = tree
    return _tree_predict(left if features[feature] <= threshold else right, features) or fallback


def _forest():
    rng = random.Random(73)
    training = []
    # Explicitly synthetic scenarios; no historical observations are created.
    for stock in range(0, 101, 2):
        for demand in range(0, 41, 2):
            training.append((stock, demand, _label(stock, demand)))
    trees = []
    for _ in range(31):
        sample = [training[rng.randrange(len(training))] for _ in training]
        trees.append(_fit_tree(sample, rng))
    return trees


_TREES = _forest()


def predict_shortage_risks(inventory, demand_by_group):
    """Return per-group risks from available units and recent request demand."""
    results = []
    for row in inventory:
        group = row["blood_group"]
        features = (int(row["units"]), int(demand_by_group.get(group, 0)))
        votes = [_tree_predict(tree, features) for tree in _TREES]
        risk = max(set(votes), key=votes.count)
        results.append({"blood_group": group, "units": features[0],
                        "recent_demand": features[1], "risk": risk})
    return {"mode": MODE, "risks": results}
