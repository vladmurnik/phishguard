// Tiny inference engine for the exported LightGBM forest.
// No dependencies, no WASM, no eval: ~60 lines of tree traversal.
//
// The score is decomposed exactly:  raw = base + sum(contributions)
// where base folds the model's init_score plus the mean leaf of every tree.
// That makes the popup's "why" list a real additive explanation, not a guess.

export function prepare(model) {
  const trees = model.trees.map((flat) => {
    const mean = new Float64Array(flat.length);
    const walk = (i) => {
      const n = flat[i];
      if (n.f < 0) {
        mean[i] = n.v;
        return n.v;
      }
      const l = walk(n.l);
      const r = walk(n.r);
      mean[i] = (l + r) / 2;
      return mean[i];
    };
    walk(0);
    return { flat, mean };
  });
  const base = model.init_score + trees.reduce((s, t) => s + t.mean[0], 0);
  return { trees, base, nFeatures: model.n_features, names: model.feature_names };
}

export function score(prepared, x) {
  const contrib = new Float64Array(prepared.nFeatures);
  for (const { flat, mean } of prepared.trees) {
    let i = 0;
    let guard = 0;
    while (flat[i].f >= 0 && guard++ < 64) {
      const n = flat[i];
      const child = x[n.f] <= n.t ? n.l : n.r;
      contrib[n.f] += mean[child] - mean[i];
      i = child;
    }
  }
  let raw = prepared.base;
  for (let k = 0; k < contrib.length; k += 1) raw += contrib[k];
  return { p: 1 / (1 + Math.exp(-raw)), raw, contrib };
}

export function explain(prepared, x, scoreResult, top = 4) {
  const items = [];
  for (let k = 0; k < scoreResult.contrib.length; k += 1) {
    if (scoreResult.contrib[k] === 0) continue;
    items.push({ name: prepared.names[k], value: x[k], weight: scoreResult.contrib[k] });
  }
  items.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));
  return items.slice(0, top);
}

export function verdict(p) {
  if (p >= 0.75) return "danger";
  if (p >= 0.45) return "warn";
  return "safe";
}
