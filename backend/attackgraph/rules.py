from __future__ import annotations

RULES: dict[str, dict[str, str]] = {
    "R-AUTH-01": {
        "kind": "relationship",
        "title": "Successful logon",
        "description": "A successful authentication record naming a user and a destination host creates "
        "user -AUTHENTICATED_TO-> host. Failed logons are retained as events but create no access edge.",
    },
    "R-AUTH-02": {
        "kind": "relationship",
        "title": "Remote logon origin",
        "description": "A successful logon whose source host differs from its destination host creates "
        "source -CONNECTED_TO-> destination, because the source machine held a session on the destination.",
    },
    "R-PROC-01": {
        "kind": "relationship",
        "title": "Process execution",
        "description": "An EDR process-start record creates host -EXECUTED-> process. The process node is "
        "keyed by host, image name and PID, so separate executions remain distinct.",
    },
    "R-PROC-02": {
        "kind": "relationship",
        "title": "Parent/child process",
        "description": "When the EDR record names a parent image and PID, parent -SPAWNED-> child is created.",
    },
    "R-NET-01": {
        "kind": "relationship",
        "title": "Process network connection",
        "description": "An EDR network-connect record creates process -CONNECTED_TO-> destination "
        "(or -COMMUNICATED_WITH-> for a public IP address).",
    },
    "R-NET-02": {
        "kind": "relationship",
        "title": "Allowed firewall flow",
        "description": "An allowed firewall flow creates source -CONNECTED_TO-> destination (or -COMMUNICATED_WITH-> "
        "for a public IP address). Blocked flows create no edge.",
    },
    "R-DNS-01": {
        "kind": "relationship",
        "title": "DNS lookup",
        "description": "A DNS query record creates client -QUERIED-> domain.",
    },
    "R-DNS-02": {
        "kind": "relationship",
        "title": "DNS answer",
        "description": "A DNS answer creates domain -RESOLVED_TO-> ip for the first IP address in the answer.",
    },
    "R-DB-01": {
        "kind": "relationship",
        "title": "Database session",
        "description": "A database audit record creates client host -ACCESSED-> database.",
    },
    "R-PRIV-01": {
        "kind": "relationship",
        "title": "Credential / token acquisition",
        "description": "An EDR credential-access record that names a target account creates "
        "process -PRIVILEGE_ESCALATED-> user: the process obtained material usable as that account.",
    },
    "R-SVC-01": {
        "kind": "relationship",
        "title": "Service installation",
        "description": "An EDR service-install record creates process -MODIFIED-> service.",
    },
    "R-ALERT-01": {
        "kind": "context",
        "title": "Alert subject",
        "description": "A SIEM alert creates alert -ALERTED_ON-> entity for each entity the alert names. "
        "These context edges are shown for explanation but never traversed by path or blast-radius search.",
    },
    "R-RES-01": {
        "kind": "resolution",
        "title": "IP-to-host resolution",
        "description": "An IP address is replaced by a host only when the asset inventory explicitly assigns "
        "that IP to that host. Occurrences that depend on this resolution are marked INFERRED.",
    },
    "R-SUSP-00": {
        "kind": "suspicion",
        "title": "Native severity",
        "description": "An occurrence inherits the severity reported by its own source record (0..1).",
    },
    "R-SUSP-01": {
        "kind": "suspicion",
        "title": "Alert evidence reference",
        "description": "When an alert lists an event in its evidence references, every occurrence created by that "
        "event inherits the alert severity (unless the alert disposition is benign or false positive).",
    },
    "R-SUSP-02": {
        "kind": "suspicion",
        "title": "Alert subject proximity",
        "description": "An occurrence whose two endpoints are both named by the same alert (a process counts as its "
        "host) and that lies within the correlation window of that alert receives 0.8 x the alert severity.",
    },
    "R-SUSP-03": {
        "kind": "suspicion",
        "title": "MD behavioural deviation",
        "description": "Robust Mahalanobis distance of the occurrence (time of day, data volume, relationship novelty) from "
        "its peer baseline (the pair's own history, else its relationship type). Above D² 18.47 it contributes suspicion up "
        "to 0.45, deliberately below the 0.5 threshold, so deviation alone never makes anything 'suspected'.",
    },
    "R-COR-01": {
        "kind": "correlation",
        "title": "Shared entity within window",
        "description": "Two seed signals are grouped when they reference the same entity and occur within the "
        "configured correlation window of each other.",
    },
    "R-COR-02": {
        "kind": "correlation",
        "title": "Graph adjacency within window",
        "description": "Two seed signals are grouped when an entity of one is directly connected in the graph to an "
        "entity of the other by an occurrence inside the correlation window.",
    },
    "R-COR-03": {
        "kind": "correlation",
        "title": "Explicit evidence reference",
        "description": "An alert and the events it lists as evidence are always placed in the same incident.",
    },
}

DISMISSED_DISPOSITIONS = {"benign", "benign_true_positive", "false_positive", "closed_benign"}
