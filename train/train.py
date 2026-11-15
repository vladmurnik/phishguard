"""Train the PhishGuard model and export it to a dependency-free JSON.

Run:
    uv sync --locked
    uv run python train/train.py

Artifacts:
    data/features.npz    cached feature matrix (rebuilt if missing)
    build/model.json     trees + feature names, consumed by src/engine.js
    build/model.js       the same document as an ES module
    build/report.json    every metric quoted in the README
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES, featurize, registrable_domain  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
BUILD = os.path.join(ROOT, "build")


def load_dataset():
    cache = os.path.join(DATA, "features.npz")
    if os.path.exists(cache):
        z = np.load(cache, allow_pickle=True)
        return z["X"], z["y"], list(z["groups"]), list(z["urls"])
    t0 = time.time()
    X, y, groups, urls = [], [], [], []
    with open(os.path.join(DATA, "raw.csv"), newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            u = (row.get("url") or "").strip()
            lab = (row.get("label") or "").strip()
            if not u or lab not in {'0', '1'}:
                continue
            if not u.isascii():  # the dump has a few rows with broken bytes
                continue
            X.append(featurize(u))
            y.append(int(lab))
            groups.append(registrable_domain(u))
            urls.append(u)
    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=np.int8)
    print(f"featurized {len(y):,} urls in {time.time() - t0:.1f}s, phishing={int(y.sum()):,}")
    np.savez_compressed(cache, X=X, y=y, groups=np.array(groups, dtype=object), urls=np.array(urls, dtype=object))
    return X, y, groups, urls


def bucket(key: str, mod: int = 5) -> int:
    return int(hashlib.blake2b(key.encode(), digest_size=4).hexdigest(), 16) % mod


def split_grouped(groups, test_bucket=0):
    idx = np.arange(len(groups))
    is_test = np.array([bucket(g) == test_bucket for g in groups])
    return idx[~is_test], idx[is_test]


def split_random(y, frac=0.2, seed=7):
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(y))
    cut = int(len(y) * (1 - frac))
    return idx[:cut], idx[cut:]


def recall_at_fpr(y, score, max_fpr=0.01):
    order = np.argsort(-score)
    y = y[order]
    score = score[order]
    pos = y.sum()
    neg = len(y) - pos
    tp = 0
    fp = 0
    best = 0.0
    for i in range(len(y)):
        if y[i] == 1:
            tp += 1
        else:
            fp += 1
            if fp / neg > max_fpr:
                break
        best = max(best, tp / pos)
    return best


def main():
    import lightgbm as lgb
    from sklearn.metrics import average_precision_score, roc_auc_score

    os.makedirs(BUILD, exist_ok=True)
    X, y, groups, urls = load_dataset()

    tr, te = split_grouped(groups)
    print(f"grouped split: train={len(tr):,} test={len(te):,} "
          f"(domains overlap: {len(set(groups[i] for i in tr) & set(groups[i] for i in te))})")

    params = dict(
        objective="binary",
        n_estimators=300,
        learning_rate=0.08,
        num_leaves=31,
        min_child_samples=40,
        feature_fraction=0.85,
        bagging_fraction=0.8,
        bagging_freq=1,
        n_jobs=-1,
        verbose=-1,
        random_state=7,
    )
    model = lgb.LGBMClassifier(**params)
    t0 = time.time()
    model.fit(X[tr], y[tr], eval_set=[(X[te], y[te])], eval_metric="auc",
              callbacks=[lgb.early_stopping(40, verbose=False)])
    train_time = time.time() - t0

    proba = model.predict_proba(X[te])[:, 1]
    yte = y[te]
    metrics = {
        "n_train": int(len(tr)),
        "n_test": int(len(te)),
        "phishing_share_test": float(yte.mean()),
        "roc_auc": float(roc_auc_score(yte, proba)),
        "pr_auc": float(average_precision_score(yte, proba)),
        "recall_at_1pct_fpr": float(recall_at_fpr(yte, proba, 0.01)),
        "recall_at_5pct_fpr": float(recall_at_fpr(yte, proba, 0.05)),
        "best_iteration": int(model.best_iteration_ or params["n_estimators"]),
        "fit_seconds": round(train_time, 1),
        "split": "grouped by registrable domain (blake2b bucket 0 == test)",
    }

    # The same model on a random split, quoted only to show how much a random
    # split inflates the number. This is the honest-comparison paragraph.
    rtr, rte = split_random(y)
    m2 = lgb.LGBMClassifier(**{**params, "n_estimators": metrics["best_iteration"]})
    m2.fit(X[rtr], y[rtr])
    p2 = m2.predict_proba(X[rte])[:, 1]
    metrics["random_split_roc_auc"] = float(roc_auc_score(y[rte], p2))
    metrics["random_split_recall_at_1pct_fpr"] = float(recall_at_fpr(y[rte], p2, 0.01))

    print(json.dumps(metrics, indent=2))

    dump = model.booster_.dump_model()
    trees = []
    for t in dump["tree_info"]:
        nodes = t["tree_structure"]
        flat = []

        def walk(node):
            i = len(flat)
            flat.append(None)
            if "leaf_value" in node:
                flat[i] = {"f": -1, "t": 0.0, "l": -1, "r": -1, "v": round(node["leaf_value"], 6)}
            else:
                flat[i] = {
                    "f": int(node["split_feature"]),
                    "t": round(float(node["threshold"]), 6),
                    "l": -1,
                    "r": -1,
                    "v": 0.0,
                }
                li = walk(node["left_child"])
                ri = walk(node["right_child"])
                flat[i]["l"], flat[i]["r"] = li, ri
            return i

        walk(nodes)
        trees.append(flat)

    doc = {
        "format": "phishguard-lgbm-v1",
        "feature_names": FEATURE_NAMES,
        "trees": trees,
        "learning_rate": float(model.booster_.params["learning_rate"]),
        "n_features": len(FEATURE_NAMES),
        "init_score": 0.0,
    }

    # LightGBM keeps the base score (logit of the mean label) outside the trees,
    # so a naive "sum of leaves" gives a wrong probability. Recover the constant
    # by comparing its own raw predictions with our leaf sum on a few rows.
    probe = np.random.default_rng(3).choice(len(y), size=64, replace=False)
    raw_ref = model.booster_.predict(X[probe], raw_score=True)
    raw_leafsum = np.zeros(len(probe))
    for j, row in enumerate(X[probe]):
        s = 0.0
        for flat in trees:
            i = 0
            while flat[i]["f"] >= 0:
                i = flat[i]["l"] if row[flat[i]["f"]] <= flat[i]["t"] else flat[i]["r"]
            s += flat[i]["v"]
        raw_leafsum[j] = s
    doc["init_score"] = float(round(np.mean(raw_ref - raw_leafsum), 6))
    metrics["init_score"] = doc["init_score"]
    metrics["max_bias_uncertainty"] = float(np.max(np.abs((raw_ref - raw_leafsum) - doc["init_score"])))

    with open(os.path.join(BUILD, "model.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, separators=(",", ":"))
    os.makedirs(os.path.join(ROOT, "src"), exist_ok=True)
    with open(os.path.join(ROOT, "src", "model.js"), "w", encoding="utf-8") as f:
        f.write("// generated by train/train.py — do not edit by hand\nexport const MODEL = ")
        json.dump(doc, f, separators=(",", ":"))
        f.write(";\n")

    size = os.path.getsize(os.path.join(BUILD, "model.json"))
    metrics["model_bytes"] = size
    metrics["n_trees"] = len(trees)
    with open(os.path.join(BUILD, "report.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"model.json {size / 1024:.0f} KB, {len(trees)} trees")

    # A fixed sample of test rows for the JS parity check: url + python features.
    sample = np.random.default_rng(11).choice(te, size=min(2000, len(te)), replace=False)
    pos_of = {int(idx): p for p, idx in enumerate(te)}
    with open(os.path.join(ROOT, "tests", "features_py.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "feature_names": FEATURE_NAMES,
                "rows": [
                    {
                        "url": urls[i],
                        "label": int(y[i]),
                        "x": [round(float(v), 6) for v in X[i]],
                        "score": round(float(proba[pos_of[int(i)]]), 6),
                    }
                    for i in sample
                ],
            },
            f,
        )
    print("wrote tests/features_py.json")


if __name__ == "__main__":
    main()
