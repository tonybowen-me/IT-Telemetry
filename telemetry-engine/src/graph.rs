/// Lightweight in-memory causal graph.
///
/// Nodes  = entities (users, batches).
/// Edges  = required causal transitions between event types.
/// Satisfied edges print green; broken edges print red (ANSI).
use std::collections::HashSet;

// ── ANSI colours ────────────────────────────────────────────────────────────

const GREEN: &str  = "\x1b[32m";
const RED: &str    = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str   = "\x1b[36m";
const BOLD: &str   = "\x1b[1m";
const DIM: &str    = "\x1b[2m";
const RESET: &str  = "\x1b[0m";

// ── Node ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeKind {
    User,
    Batch,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    pub id:   String,
    pub kind: NodeKind,
}

impl Node {
    pub fn user(id: impl Into<String>) -> Self {
        Self { id: id.into(), kind: NodeKind::User }
    }
    pub fn batch(id: impl Into<String>) -> Self {
        Self { id: id.into(), kind: NodeKind::Batch }
    }
}

// ── Edge ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CausalEdge {
    pub entity:     String,
    pub from_event: &'static str,
    pub to_event:   &'static str,
    /// `true`  = the causal link was observed in the event stream.
    /// `false` = the required successor event was MISSING — broken contract.
    pub satisfied:  bool,
}

// ── Graph ────────────────────────────────────────────────────────────────────

pub struct CausalGraph {
    pub nodes: HashSet<Node>,
    pub edges: Vec<CausalEdge>,
}

impl CausalGraph {
    pub fn new() -> Self {
        Self { nodes: HashSet::new(), edges: Vec::new() }
    }

    pub fn add_node(&mut self, node: Node) {
        self.nodes.insert(node);
    }

    pub fn add_edge(
        &mut self,
        entity: impl Into<String>,
        from_event: &'static str,
        to_event: &'static str,
        satisfied: bool,
    ) {
        self.edges.push(CausalEdge {
            entity:     entity.into(),
            from_event,
            to_event,
            satisfied,
        });
    }

    /// Pretty-print the graph to stdout with ANSI colouring.
    pub fn print(&self) {
        let bar = format!("{DIM}{}{RESET}", "─".repeat(68));
        println!("\n{bar}");
        println!("  {BOLD}{CYAN}CAUSAL GRAPH — required transition analysis{RESET}");
        println!("{bar}");
        println!("  {GREEN}✔ green{RESET} = contract edge satisfied");
        println!("  {RED}✘ red  {RESET} = required successor MISSING  ← broken contract");
        println!("{bar}");

        // Group edges by entity for readability
        let mut entities: Vec<&str> = self
            .edges
            .iter()
            .map(|e| e.entity.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        entities.sort();

        for entity in entities {
            let entity_edges: Vec<&CausalEdge> =
                self.edges.iter().filter(|e| e.entity == entity).collect();

            // Find entity kind for label
            let kind_label = if self.nodes.contains(&Node::batch(entity)) {
                "batch"
            } else {
                "user "
            };

            println!(
                "\n  {BOLD}{YELLOW}[{kind_label}: {entity}]{RESET}"
            );

            for edge in entity_edges {
                let (color, sym) = if edge.satisfied {
                    (GREEN, "✔")
                } else {
                    (RED, "✘")
                };
                println!(
                    "    {color}{sym}  {from:<22} →  {to}{RESET}",
                    color = color,
                    sym   = sym,
                    from  = edge.from_event,
                    to    = edge.to_event,
                );
            }
        }

        println!("\n{bar}");
    }
}
