/// Dependency analysis and conflict detection for parallel transaction execution.
///
/// This module models the dependency graph between transactions in a block,
/// allowing the scheduler to identify which transactions are safe to execute
/// concurrently and which must be serialised.
///
/// Items:
/// 1  `DependencyGraph` struct
/// 2  `record_rw_set` - store read/write set per transaction
/// 3  `detect_overlaps` - find overlapping state keys
/// 4  `build_edges` - construct directed dependency edges
/// 5  `independent_transactions` - txs with no predecessors
/// 6  `parallel_batches` - group independent txs for concurrent execution
/// 7  `detect_cycles` - identify cyclic dependencies (Kahn / DFS)
/// 8  `resolve_cycle` - break cycles by marking txs for re-execution
/// 9  `deterministic_order` - canonical topological sort (stable, deterministic)
/// 10 `export` - serialisable snapshot of the graph for debugging
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

//  item 1: DependencyGraph

/// A directed acyclic dependency graph over block transactions.
///
/// Each node is a transaction index.  A directed edge `(a  b)` means
/// "b must execute after a" (b depends on a).
///
/// The graph is built lazily: call `record_rw_set` for every transaction,
/// then `build_edges` to populate the edge list.
#[derive(Clone, Debug, Default)]
pub struct DependencyGraph {
    /// item 2: per-tx read/write sets
    rw_sets: HashMap<usize, ReadWriteSet>,
    /// item 4: adjacency list  tx_index  set of successors that depend on it
    edges: HashMap<usize, HashSet<usize>>,
    /// item 4: reverse adjacency  tx_index  set of predecessors it waits for
    predecessors: HashMap<usize, HashSet<usize>>,
    /// Total number of transactions in the block.
    total_tx: usize,
    /// item 3: set of (key, writer_tx, reader_tx) conflict records
    overlaps: Vec<KeyOverlap>,
    /// item 8: transactions flagged for re-execution after cycle breaking
    reexecution_set: HashSet<usize>,
}

/// A single overlapping-key record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyOverlap {
    pub key: Vec<u8>,
    pub overlap_type: OverlapType,
    pub tx_a: usize,
    pub tx_b: usize,
}

/// The flavour of key overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverlapType {
    /// tx_b reads a key tx_a writes.
    ReadAfterWrite,
    /// tx_b writes a key tx_a writes.
    WriteAfterWrite,
    /// tx_b writes a key tx_a reads.
    WriteAfterRead,
}

impl DependencyGraph {
    pub fn new(total_tx: usize) -> Self {
        Self {
            rw_sets: HashMap::new(),
            edges: HashMap::new(),
            predecessors: HashMap::new(),
            total_tx,
            overlaps: Vec::new(),
            reexecution_set: HashSet::new(),
        }
    }

    //  item 2: record read/write sets

    /// Registers the read/write set for `tx_index`.
    ///
    /// Call once per transaction before calling `build_edges`.
    pub fn record_rw_set(&mut self, tx_index: usize, rws: ReadWriteSet) {
        self.total_tx = self.total_tx.max(tx_index + 1);
        self.rw_sets.insert(tx_index, rws);
    }

    pub fn rw_set(&self, tx_index: usize) -> Option<&ReadWriteSet> {
        self.rw_sets.get(&tx_index)
    }

    //  item 3: detect overlapping state keys

    /// Computes all overlapping keys between every pair of recorded transactions
    /// and stores them as `KeyOverlap` records.
    ///
    /// Must be called before `build_edges`.
    pub fn detect_overlaps(&mut self) {
        self.overlaps.clear();
        let mut indices: Vec<usize> = self.rw_sets.keys().copied().collect();
        indices.sort_unstable();

        for i in 0..indices.len() {
            for j in (i + 1)..indices.len() {
                let a = indices[i];
                let b = indices[j];
                let (lo, hi) = if a < b { (a, b) } else { (b, a) };
                let rws_lo = &self.rw_sets[&lo];
                let rws_hi = &self.rw_sets[&hi];

                // RAW: hi reads what lo writes
                for key in rws_lo.write_set.iter() {
                    if rws_hi.read_set.contains(key) {
                        self.overlaps.push(KeyOverlap {
                            key: key.clone(),
                            overlap_type: OverlapType::ReadAfterWrite,
                            tx_a: lo,
                            tx_b: hi,
                        });
                    }
                }

                // WAW: both write the same key
                for key in rws_lo.write_set.iter() {
                    if rws_hi.write_set.contains(key) {
                        self.overlaps.push(KeyOverlap {
                            key: key.clone(),
                            overlap_type: OverlapType::WriteAfterWrite,
                            tx_a: lo,
                            tx_b: hi,
                        });
                    }
                }

                // WAR: hi writes what lo reads
                for key in rws_lo.read_set.iter() {
                    if rws_hi.write_set.contains(key) {
                        self.overlaps.push(KeyOverlap {
                            key: key.clone(),
                            overlap_type: OverlapType::WriteAfterRead,
                            tx_a: lo,
                            tx_b: hi,
                        });
                    }
                }
            }
        }
    }

    pub fn overlaps(&self) -> &[KeyOverlap] {
        &self.overlaps
    }

    //  item 4: build dependency edges

    /// Builds directed edges from the recorded `KeyOverlap`s.
    ///
    /// For all overlap types the convention is: the transaction with the
    /// **lower index** is the "writer / earlier" side, so the edge goes
    /// `lo  hi` (hi must wait for lo).  This preserves block order and
    /// makes the graph acyclic in the absence of pathological patterns.
    ///
    /// Returns `&self` for chaining.
    pub fn build_edges(&mut self) {
        self.edges.clear();
        self.predecessors.clear();

        // Initialise maps for every known tx so independent nodes are visible.
        for &idx in self.rw_sets.keys() {
            self.edges.entry(idx).or_default();
            self.predecessors.entry(idx).or_default();
        }

        for overlap in &self.overlaps {
            let (from, to) = (overlap.tx_a, overlap.tx_b);
            self.edges.entry(from).or_default().insert(to);
            self.predecessors.entry(to).or_default().insert(from);
        }
    }

    /// Adds a single directed edge `from  to` (to depends on from).
    pub fn add_edge(&mut self, from: usize, to: usize) {
        self.edges.entry(from).or_default().insert(to);
        self.predecessors.entry(to).or_default().insert(from);
    }

    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|s| s.len()).sum()
    }

    pub fn successors(&self, tx_index: usize) -> impl Iterator<Item = usize> + '_ {
        self.edges
            .get(&tx_index)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    pub fn predecessors_of(&self, tx_index: usize) -> impl Iterator<Item = usize> + '_ {
        self.predecessors
            .get(&tx_index)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    //  item 5: identify independent transactions

    /// Returns the set of transactions that have **no predecessors** - i.e.
    /// they can begin execution immediately, independently of all others.
    pub fn independent_transactions(&self) -> Vec<usize> {
        let mut result: Vec<usize> = self
            .rw_sets
            .keys()
            .copied()
            .filter(|idx| {
                self.predecessors
                    .get(idx)
                    .map(|s| s.is_empty())
                    .unwrap_or(true)
            })
            .collect();
        result.sort_unstable(); // item 9: deterministic order
        result
    }

    //  item 6: parallel execution batches

    /// Partitions all transactions into an ordered list of **parallel batches**.
    ///
    /// Each batch contains transactions that are mutually independent and whose
    /// entire predecessor set has already been placed in an earlier batch.
    ///
    /// This is equivalent to computing the topological levels (BFS layers) of
    /// the DAG.  Transactions within a batch are safe to execute concurrently.
    ///
    /// Returns `Err` if a cycle is detected (use `detect_cycles` / `resolve_cycle`
    /// to handle cycles before calling this).
    pub fn parallel_batches(&self) -> Result<Vec<Vec<usize>>> {
        let mut in_degree: HashMap<usize, usize> = self
            .rw_sets
            .keys()
            .map(|&k| {
                let d = self.predecessors.get(&k).map(|s| s.len()).unwrap_or(0);
                (k, d)
            })
            .collect();

        let mut queue: VecDeque<usize> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&k, _)| k)
            .collect();
        // item 9: deterministic order within each level
        let mut sorted_queue: Vec<usize> = queue.drain(..).collect();
        sorted_queue.sort_unstable();
        queue.extend(sorted_queue);

        let mut batches: Vec<Vec<usize>> = Vec::new();
        let mut placed = 0usize;

        while !queue.is_empty() {
            // Drain the current zero-in-degree frontier  one batch.
            let batch_size = queue.len();
            let mut batch: Vec<usize> = queue.drain(..batch_size).collect();
            batch.sort_unstable(); // item 9
            placed += batch.len();

            // Reduce in-degree for successors.
            let mut next: Vec<usize> = Vec::new();
            for &tx in &batch {
                if let Some(succs) = self.edges.get(&tx) {
                    for &s in succs {
                        let d = in_degree.entry(s).or_insert(1);
                        *d = d.saturating_sub(1);
                        if *d == 0 {
                            next.push(s);
                        }
                    }
                }
            }
            next.sort_unstable(); // item 9
            queue.extend(next);
            batches.push(batch);
        }

        if placed != self.rw_sets.len() {
            return Err(anyhow!(
                "cycle detected: only {}/{} transactions placed",
                placed,
                self.rw_sets.len()
            ));
        }
        Ok(batches)
    }

    //  item 7: detect cyclic dependencies

    /// Returns all sets of transaction indices that form strongly-connected
    /// components (cycles) in the dependency graph.
    ///
    /// Uses iterative DFS with colouring.  An empty return means the graph is a
    /// valid DAG.
    pub fn detect_cycles(&self) -> Vec<Vec<usize>> {
        // 0 = white (unvisited), 1 = grey (on stack), 2 = black (done)
        let mut color: HashMap<usize, u8> = self.rw_sets.keys().map(|&k| (k, 0)).collect();
        let mut cycles: Vec<Vec<usize>> = Vec::new();

        let mut all_nodes: Vec<usize> = self.rw_sets.keys().copied().collect();
        all_nodes.sort_unstable(); // item 9: deterministic detection order

        for &start in &all_nodes {
            if *color.get(&start).unwrap_or(&2) != 0 {
                continue;
            }
            // Iterative DFS.
            let mut stack: Vec<(usize, Vec<usize>)> = vec![(start, vec![start])];
            while let Some((node, path)) = stack.last().cloned() {
                *color.entry(node).or_insert(0) = 1; // grey

                let succs: Vec<usize> = self
                    .edges
                    .get(&node)
                    .map(|s| {
                        let mut v: Vec<usize> = s.iter().copied().collect();
                        v.sort_unstable();
                        v
                    })
                    .unwrap_or_default();

                let mut pushed = false;
                for succ in succs {
                    match color.get(&succ).copied().unwrap_or(0) {
                        1 => {
                            // Back edge  cycle
                            if let Some(start) = path.iter().position(|&n| n == succ) {
                                cycles.push(path[start..].to_vec());
                            }
                        }
                        0 => {
                            let mut new_path = path.clone();
                            new_path.push(succ);
                            stack.push((succ, new_path));
                            pushed = true;
                            break;
                        }
                        _ => {}
                    }
                }

                if !pushed {
                    *color.entry(node).or_insert(0) = 2; // black
                    stack.pop();
                }
            }
        }

        cycles
    }

    pub fn has_cycle(&self) -> bool {
        !self.detect_cycles().is_empty()
    }

    //  item 8: resolve cycles via re-execution

    /// Breaks all detected cycles by removing the back-edge whose **destination**
    /// has the highest `tx_index` (later transaction loses).  The removed
    /// transaction is added to `reexecution_set` so the scheduler can re-run it
    /// after its predecessors commit.
    ///
    /// For each cycle, the transaction with the highest index in the cycle is
    /// treated as the "loser": all its incoming edges from cycle members are
    /// removed, the loser is added to `reexecution_set`, and the process repeats
    /// until no cycles remain.
    ///
    /// Returns the set of transactions marked for re-execution.
    pub fn resolve_cycles(&mut self) -> HashSet<usize> {
        loop {
            let cycles = self.detect_cycles();
            if cycles.is_empty() {
                break;
            }

            for cycle in cycles {
                // Pick the highest-index tx as the one to remove edges into.
                let loser = *cycle.iter().max().unwrap();
                self.reexecution_set.insert(loser);

                // Remove all edges from cycle members pointing into loser.
                for &member in &cycle {
                    if let Some(succs) = self.edges.get_mut(&member) {
                        succs.remove(&loser);
                    }
                    if let Some(preds) = self.predecessors.get_mut(&loser) {
                        preds.remove(&member);
                    }
                }
            }
        }

        self.reexecution_set.clone()
    }

    pub fn reexecution_set(&self) -> &HashSet<usize> {
        &self.reexecution_set
    }

    //  item 9: deterministic dependency order

    /// Returns a deterministic total order of all transactions that respects
    /// every dependency edge.
    ///
    /// Within each topological level, ties are broken by `tx_index` ascending,
    /// ensuring the same block always produces the same ordering regardless of
    /// HashMap iteration order.
    ///
    /// Returns `Err` if the graph still contains a cycle (call `resolve_cycles`
    /// first).
    pub fn deterministic_order(&self) -> Result<Vec<usize>> {
        let batches = self.parallel_batches()?;
        // Each batch is already sorted ascending (item 6 ensures this).
        Ok(batches.into_iter().flatten().collect())
    }

    //  item 10: export dependency graph

    /// Produces a fully serialisable snapshot of the graph for external tooling,
    /// logging, or debugging.
    pub fn export(&self) -> DependencyGraphExport {
        let nodes: Vec<NodeExport> = self
            .rw_sets
            .iter()
            .map(|(&idx, rws)| NodeExport {
                tx_index: idx,
                read_set: rws.read_set.iter().map(|k| hex_key(k)).collect(),
                write_set: rws.write_set.iter().map(|k| hex_key(k)).collect(),
                is_independent: self
                    .predecessors
                    .get(&idx)
                    .map(|s| s.is_empty())
                    .unwrap_or(true),
                flagged_for_reexecution: self.reexecution_set.contains(&idx),
            })
            .collect();

        let mut edges: Vec<EdgeExport> = self
            .edges
            .iter()
            .flat_map(|(&from, succs)| succs.iter().map(move |&to| EdgeExport { from, to }))
            .collect();
        edges.sort_by_key(|e| (e.from, e.to)); // item 9: deterministic export

        let overlaps: Vec<OverlapExport> = self
            .overlaps
            .iter()
            .map(|o| OverlapExport {
                key: hex_key(&o.key),
                overlap_type: format!("{:?}", o.overlap_type),
                tx_a: o.tx_a,
                tx_b: o.tx_b,
            })
            .collect();

        DependencyGraphExport {
            total_tx: self.total_tx,
            nodes,
            edges,
            overlaps,
            cycle_free: !self.has_cycle(),
            reexecution_count: self.reexecution_set.len(),
        }
    }
}

fn hex_key(k: &[u8]) -> String {
    k.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Serialisable export of the full dependency graph (item 10).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyGraphExport {
    pub total_tx: usize,
    pub nodes: Vec<NodeExport>,
    pub edges: Vec<EdgeExport>,
    pub overlaps: Vec<OverlapExport>,
    pub cycle_free: bool,
    pub reexecution_count: usize,
}

impl DependencyGraphExport {
    /// Serialises to compact JSON (for log output / RPC debug endpoint).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeExport {
    pub tx_index: usize,
    pub read_set: Vec<String>,
    pub write_set: Vec<String>,
    pub is_independent: bool,
    pub flagged_for_reexecution: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgeExport {
    pub from: usize,
    pub to: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverlapExport {
    pub key: String,
    pub overlap_type: String,
    pub tx_a: usize,
    pub tx_b: usize,
}

//  Legacy types & helpers
// Kept verbatim so existing callers (executor, scheduler, commit) continue to compile.

/// The set of storage keys a transaction reads from and writes to.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReadWriteSet {
    pub read_set: Vec<Vec<u8>>,
    pub write_set: Vec<Vec<u8>>,
}

impl ReadWriteSet {
    pub fn new(read_set: Vec<Vec<u8>>, write_set: Vec<Vec<u8>>) -> Self {
        Self {
            read_set,
            write_set,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.read_set.is_empty() && self.write_set.is_empty()
    }

    pub fn read_set_as_set(&self) -> HashSet<&[u8]> {
        self.read_set.iter().map(|v| v.as_slice()).collect()
    }

    pub fn write_set_as_set(&self) -> HashSet<&[u8]> {
        self.write_set.iter().map(|v| v.as_slice()).collect()
    }

    pub fn add_read(&mut self, key: Vec<u8>) {
        if !self.read_set.contains(&key) {
            self.read_set.push(key);
        }
    }

    pub fn add_write(&mut self, key: Vec<u8>) {
        if !self.write_set.contains(&key) {
            self.write_set.push(key);
        }
    }

    /// RAW: returns keys in read_set that are also in other's write_set.
    pub fn raw_conflicts_with(&self, other: &ReadWriteSet) -> Vec<Vec<u8>> {
        let ws = other.write_set_as_set();
        self.read_set
            .iter()
            .filter(|k| ws.contains(k.as_slice()))
            .cloned()
            .collect()
    }

    /// WAR / WAW: returns keys in write_set that are also in other's read_set or write_set.
    pub fn war_or_waw_conflicts_with(&self, other: &ReadWriteSet) -> Vec<Vec<u8>> {
        let mut rs = other.read_set_as_set();
        rs.extend(other.write_set_as_set());
        self.write_set
            .iter()
            .filter(|k| rs.contains(k.as_slice()))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionConflict {
    ReadAfterWrite {
        reader: usize,
        writer: usize,
        conflicted_keys: Vec<Vec<u8>>,
    },
    WriteAfterRead {
        writer: usize,
        reader: usize,
        conflicted_keys: Vec<Vec<u8>>,
    },
    WriteAfterWrite {
        first: usize,
        second: usize,
        conflicted_keys: Vec<Vec<u8>>,
    },
}

impl TransactionConflict {
    pub fn conflicted_keys(&self) -> &[Vec<u8>] {
        match self {
            Self::ReadAfterWrite {
                conflicted_keys, ..
            }
            | Self::WriteAfterRead {
                conflicted_keys, ..
            }
            | Self::WriteAfterWrite {
                conflicted_keys, ..
            } => conflicted_keys,
        }
    }
    pub fn must_execute_first(&self) -> usize {
        match self {
            Self::ReadAfterWrite { writer, .. } => *writer,
            Self::WriteAfterRead { writer, .. } => *writer,
            Self::WriteAfterWrite { first, .. } => *first,
        }
    }
    pub fn must_execute_second(&self) -> usize {
        match self {
            Self::ReadAfterWrite { reader, .. } => *reader,
            Self::WriteAfterRead { reader, .. } => *reader,
            Self::WriteAfterWrite { second, .. } => *second,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dependency {
    pub from: usize,
    pub to: usize,
    pub conflict: TransactionConflict,
}

#[derive(Clone, Debug, Default)]
pub struct ConflictDetector {
    pub conflicts: Vec<TransactionConflict>,
    pub dependencies: Vec<Dependency>,
}

impl ConflictDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect_conflicts(&mut self, index: usize, rws: &ReadWriteSet, all_rws: &[ReadWriteSet]) {
        for (other_idx, other) in all_rws.iter().enumerate() {
            if other_idx <= index {
                continue;
            }

            let raw = other.raw_conflicts_with(rws);
            let has_raw = !raw.is_empty();
            if has_raw {
                let c = TransactionConflict::ReadAfterWrite {
                    reader: other_idx,
                    writer: index,
                    conflicted_keys: raw,
                };
                self.conflicts.push(c.clone());
                self.dependencies.push(Dependency {
                    from: index,
                    to: other_idx,
                    conflict: c,
                });
            }

            let war = rws.war_or_waw_conflicts_with(other);
            if !war.is_empty() && !has_raw {
                let c = TransactionConflict::WriteAfterRead {
                    writer: index,
                    reader: other_idx,
                    conflicted_keys: war.clone(),
                };
                self.conflicts.push(c.clone());
                self.dependencies.push(Dependency {
                    from: other_idx,
                    to: index,
                    conflict: c,
                });
            }

            let waw: Vec<Vec<u8>> = rws
                .write_set
                .iter()
                .filter(|k| other.write_set.contains(k))
                .cloned()
                .collect();
            if !waw.is_empty() {
                let c = TransactionConflict::WriteAfterWrite {
                    first: other_idx,
                    second: index,
                    conflicted_keys: waw,
                };
                self.conflicts.push(c.clone());
                self.dependencies.push(Dependency {
                    from: other_idx,
                    to: index,
                    conflict: c,
                });
            }
        }
    }
}

pub struct DependencyAnalyzer;

impl DependencyAnalyzer {
    pub fn analyze(rws_list: &[ReadWriteSet]) -> Result<HashMap<usize, Vec<usize>>> {
        let mut detector = ConflictDetector::new();
        for (i, rws) in rws_list.iter().enumerate() {
            detector.detect_conflicts(i, rws, rws_list);
        }
        let mut graph: HashMap<usize, Vec<usize>> = HashMap::new();
        for dep in &detector.dependencies {
            graph.entry(dep.to).or_default().push(dep.from);
        }
        Ok(graph)
    }

    pub fn topological_sort(
        graph: &HashMap<usize, Vec<usize>>,
        total_tx: usize,
    ) -> Result<Vec<usize>> {
        let mut in_degree = vec![0usize; total_tx];
        for (tx_idx, degree) in in_degree.iter_mut().enumerate() {
            if let Some(preds) = graph.get(&tx_idx) {
                *degree = preds.len();
            }
        }
        let mut queue: Vec<usize> = (0..total_tx).filter(|&i| in_degree[i] == 0).collect();
        let mut sorted = Vec::new();

        while !queue.is_empty() {
            let tx_idx = queue.remove(0);
            sorted.push(tx_idx);
            for (dependent, preds) in graph.iter() {
                if preds.contains(&tx_idx) {
                    in_degree[*dependent] -= 1;
                    if in_degree[*dependent] == 0 {
                        queue.push(*dependent);
                    }
                }
            }
        }

        if sorted.len() != total_tx {
            return Err(anyhow!("cycle detected in transaction dependency graph"));
        }
        Ok(sorted)
    }

    pub fn next_parallel_batch(
        graph: &HashMap<usize, Vec<usize>>,
        total_tx: usize,
        executed: &HashSet<usize>,
    ) -> Result<Vec<usize>> {
        let mut batch = Vec::new();
        for tx_idx in 0..total_tx {
            if executed.contains(&tx_idx) {
                continue;
            }
            if let Some(preds) = graph.get(&tx_idx) {
                if preds.iter().all(|&p| executed.contains(&p)) {
                    batch.push(tx_idx);
                }
            } else {
                batch.push(tx_idx);
            }
        }
        Ok(batch)
    }
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn rws(reads: &[&[u8]], writes: &[&[u8]]) -> ReadWriteSet {
        ReadWriteSet::new(
            reads.iter().map(|k| k.to_vec()).collect(),
            writes.iter().map(|k| k.to_vec()).collect(),
        )
    }

    //  item 1

    #[test]
    fn dependency_graph_new() {
        let g = DependencyGraph::new(4);
        assert_eq!(g.total_tx, 4);
        assert_eq!(g.edge_count(), 0);
    }

    //  item 2

    #[test]
    fn record_rw_set_stores_entries() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[b"a"], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[b"b"]));
        assert!(g.rw_set(0).is_some());
        assert!(g.rw_set(1).is_some());
    }

    #[test]
    fn record_rw_set_updates_total_tx() {
        let mut g = DependencyGraph::new(0);
        g.record_rw_set(7, rws(&[], &[b"y"]));
        assert_eq!(g.total_tx, 8);
    }

    //  item 3

    #[test]
    fn detect_overlaps_finds_raw() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[]));
        g.detect_overlaps();
        assert!(g
            .overlaps()
            .iter()
            .any(|o| o.overlap_type == OverlapType::ReadAfterWrite));
    }

    #[test]
    fn detect_overlaps_finds_waw() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[], &[b"x"]));
        g.detect_overlaps();
        assert!(g
            .overlaps()
            .iter()
            .any(|o| o.overlap_type == OverlapType::WriteAfterWrite));
    }

    #[test]
    fn detect_overlaps_no_conflict() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"a"]));
        g.record_rw_set(1, rws(&[], &[b"b"]));
        g.detect_overlaps();
        assert!(g.overlaps().is_empty());
    }

    //  item 4

    #[test]
    fn build_edges_creates_dependency() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[]));
        g.detect_overlaps();
        g.build_edges();
        assert!(g.successors(0).any(|s| s == 1));
        assert!(g.predecessors_of(1).any(|p| p == 0));
    }

    #[test]
    fn build_edges_no_deps_when_disjoint() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"a"]));
        g.record_rw_set(1, rws(&[], &[b"b"]));
        g.detect_overlaps();
        g.build_edges();
        assert_eq!(g.edge_count(), 0);
    }

    //  item 5

    #[test]
    fn independent_transactions_no_deps() {
        let mut g = DependencyGraph::new(3);
        g.record_rw_set(0, rws(&[], &[b"a"]));
        g.record_rw_set(1, rws(&[], &[b"b"]));
        g.record_rw_set(2, rws(&[], &[b"c"]));
        g.detect_overlaps();
        g.build_edges();
        let ind = g.independent_transactions();
        assert_eq!(ind, vec![0, 1, 2]);
    }

    #[test]
    fn independent_transactions_with_deps() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let ind = g.independent_transactions();
        assert_eq!(ind, vec![0]);
    }

    //  item 6

    #[test]
    fn parallel_batches_chain() {
        let mut g = DependencyGraph::new(3);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[b"y"]));
        g.record_rw_set(2, rws(&[b"y"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let batches = g.parallel_batches().unwrap();
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0], vec![0]);
        assert_eq!(batches[1], vec![1]);
        assert_eq!(batches[2], vec![2]);
    }

    #[test]
    fn parallel_batches_all_independent() {
        let mut g = DependencyGraph::new(4);
        for i in 0..4 {
            g.record_rw_set(i, rws(&[], &[&[i as u8]]));
        }
        g.detect_overlaps();
        g.build_edges();
        let batches = g.parallel_batches().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 4);
    }

    #[test]
    fn parallel_batches_diamond() {
        // 0  1, 0  2, 1  3, 2  3
        let mut g = DependencyGraph::new(4);
        g.record_rw_set(0, rws(&[], &[b"x", b"y"]));
        g.record_rw_set(1, rws(&[b"x"], &[b"z"]));
        g.record_rw_set(2, rws(&[b"y"], &[b"w"]));
        g.record_rw_set(3, rws(&[b"z", b"w"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let batches = g.parallel_batches().unwrap();
        assert_eq!(batches[0], vec![0]);
        assert_eq!(batches[1].len(), 2); // 1 and 2 in parallel
        assert_eq!(batches[2], vec![3]);
    }

    //  item 7

    #[test]
    fn detect_cycles_acyclic_graph() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[]));
        g.detect_overlaps();
        g.build_edges();
        assert!(!g.has_cycle());
    }

    #[test]
    fn detect_cycles_manual_cycle() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[]));
        g.record_rw_set(1, rws(&[], &[]));
        g.detect_overlaps();
        g.build_edges();
        // Manually create a cycle.
        g.add_edge(0, 1);
        g.add_edge(1, 0);
        assert!(g.has_cycle());
        let cycles = g.detect_cycles();
        assert!(!cycles.is_empty());
    }

    //  item 8

    #[test]
    fn resolve_cycles_breaks_cycle() {
        let mut g = DependencyGraph::new(3);
        g.record_rw_set(0, rws(&[], &[]));
        g.record_rw_set(1, rws(&[], &[]));
        g.record_rw_set(2, rws(&[], &[]));
        g.detect_overlaps();
        g.build_edges();
        g.add_edge(0, 1);
        g.add_edge(1, 2);
        g.add_edge(2, 0); // cycle
        let reexec = g.resolve_cycles();
        assert!(!g.has_cycle());
        assert!(!reexec.is_empty());
    }

    #[test]
    fn resolve_cycles_noop_on_dag() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let reexec = g.resolve_cycles();
        assert!(reexec.is_empty());
        assert!(!g.has_cycle());
    }

    //  item 9

    #[test]
    fn deterministic_order_stable() {
        let mut g = DependencyGraph::new(4);
        g.record_rw_set(0, rws(&[], &[b"a"]));
        g.record_rw_set(1, rws(&[], &[b"b"]));
        g.record_rw_set(2, rws(&[b"a"], &[b"c"]));
        g.record_rw_set(3, rws(&[b"b", b"c"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let order1 = g.deterministic_order().unwrap();
        let order2 = g.deterministic_order().unwrap();
        assert_eq!(order1, order2);
        assert_eq!(order1.len(), 4);
    }

    #[test]
    fn deterministic_order_respects_deps() {
        let mut g = DependencyGraph::new(3);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[b"y"]));
        g.record_rw_set(2, rws(&[b"y"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let order = g.deterministic_order().unwrap();
        let pos: HashMap<usize, usize> = order.iter().enumerate().map(|(i, &tx)| (tx, i)).collect();
        assert!(pos[&0] < pos[&1]);
        assert!(pos[&1] < pos[&2]);
    }

    //  item 10

    #[test]
    fn export_contains_all_nodes() {
        let mut g = DependencyGraph::new(3);
        for i in 0..3 {
            g.record_rw_set(i, rws(&[], &[&[i as u8]]));
        }
        g.detect_overlaps();
        g.build_edges();
        let exp = g.export();
        assert_eq!(exp.total_tx, 3);
        assert_eq!(exp.nodes.len(), 3);
    }

    #[test]
    fn export_to_json_roundtrip() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let exp = g.export();
        let json = exp.to_json().unwrap();
        assert!(json.contains("\"total_tx\":2"));
    }

    #[test]
    fn export_marks_independent_correctly() {
        let mut g = DependencyGraph::new(2);
        g.record_rw_set(0, rws(&[], &[b"x"]));
        g.record_rw_set(1, rws(&[b"x"], &[]));
        g.detect_overlaps();
        g.build_edges();
        let exp = g.export();
        let node0 = exp.nodes.iter().find(|n| n.tx_index == 0).unwrap();
        let node1 = exp.nodes.iter().find(|n| n.tx_index == 1).unwrap();
        assert!(node0.is_independent);
        assert!(!node1.is_independent);
    }

    //  Legacy helpers

    #[test]
    fn read_write_set_conflict_detection() {
        let rws1 = ReadWriteSet::new(vec![b"a".to_vec()], vec![b"x".to_vec()]);
        let rws2 = ReadWriteSet::new(vec![b"x".to_vec()], vec![b"b".to_vec()]);
        assert!(rws1.raw_conflicts_with(&rws2).is_empty());
        assert_eq!(rws2.raw_conflicts_with(&rws1), vec![b"x".to_vec()]);
    }

    #[test]
    fn dependency_analyzer_no_conflicts() {
        let list = vec![
            ReadWriteSet::new(vec![b"a".to_vec()], vec![b"x".to_vec()]),
            ReadWriteSet::new(vec![b"b".to_vec()], vec![b"y".to_vec()]),
        ];
        let graph = DependencyAnalyzer::analyze(&list).unwrap();
        assert!(graph.is_empty());
        assert_eq!(
            DependencyAnalyzer::topological_sort(&graph, 2)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn dependency_analyzer_with_conflicts() {
        let list = vec![
            ReadWriteSet::new(vec![], vec![b"x".to_vec()]),
            ReadWriteSet::new(vec![b"x".to_vec()], vec![]),
        ];
        let graph = DependencyAnalyzer::analyze(&list).unwrap();
        assert_eq!(graph.get(&1).unwrap().len(), 1);
        let sorted = DependencyAnalyzer::topological_sort(&graph, 2).unwrap();
        assert_eq!(sorted[0], 0);
        assert_eq!(sorted[1], 1);
    }

    #[test]
    fn next_parallel_batch_respects_dependencies() {
        let mut graph = HashMap::new();
        graph.insert(1, vec![0]);
        graph.insert(2, vec![1]);
        let batch0 = DependencyAnalyzer::next_parallel_batch(&graph, 3, &HashSet::new()).unwrap();
        assert_eq!(batch0, vec![0]);
        let mut executed = HashSet::new();
        executed.insert(0);
        let batch1 = DependencyAnalyzer::next_parallel_batch(&graph, 3, &executed).unwrap();
        assert_eq!(batch1, vec![1]);
    }
}
