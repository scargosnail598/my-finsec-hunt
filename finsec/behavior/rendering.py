"""Human-readable and machine-readable workflow graph rendering."""

import json

from finsec.behavior.domain import WorkflowGraph


def render_graph_text(graph: WorkflowGraph) -> str:
    """Render a compact evidence-oriented graph summary."""

    labels = {item.id: item.label for item in graph.nodes}
    lines = [f"Workflow graph {graph.id} ({graph.workflow_family_id})"]
    for edge in graph.edges:
        lines.append(
            f"- {labels[edge.source]} --{edge.action}--> {labels[edge.destination]} "
            f"[count={edge.count}, confidence={edge.confidence}]"
        )
        lines.append(f"  evidence: {', '.join(edge.observation_ids) or 'none'}")
    if not graph.edges:
        lines.append("- No transitions were inferred.")
    return "\n".join(lines)


def render_graph_dot(graph: WorkflowGraph) -> str:
    """Render deterministic Graphviz DOT without external dependencies."""

    lines = ["digraph workflow {", '  rankdir="LR";']
    for node in graph.nodes:
        shape = "doublecircle" if node.kind == "TERMINAL" else "box"
        lines.append(f'  "{node.id}" [label="{node.label}", shape={shape}];')
    for edge in graph.edges:
        label = f"{edge.action} ({edge.count})"
        lines.append(f'  "{edge.source}" -> "{edge.destination}" [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


def render_graph_mermaid(graph: WorkflowGraph) -> str:
    """Render deterministic Mermaid flowchart syntax."""

    labels = {item.id: item.label.replace('"', "'") for item in graph.nodes}
    lines = ["flowchart LR"]
    for node in graph.nodes:
        lines.append(f'  {node.id.replace("-", "_")}["{labels[node.id]}"]')
    for edge in graph.edges:
        source = edge.source.replace("-", "_")
        destination = edge.destination.replace("-", "_")
        lines.append(f'  {source} -->|"{edge.action} ({edge.count})"| {destination}')
    return "\n".join(lines)


def render_graph(graph: WorkflowGraph, output_format: str) -> str:
    """Render one of the supported stable graph formats."""

    normalized = output_format.lower()
    if normalized == "text":
        return render_graph_text(graph)
    if normalized == "json":
        return json.dumps(graph.model_dump(mode="json"), indent=2, sort_keys=True)
    if normalized == "dot":
        return render_graph_dot(graph)
    if normalized == "mermaid":
        return render_graph_mermaid(graph)
    raise ValueError("Graph format must be text, json, dot, or mermaid.")
