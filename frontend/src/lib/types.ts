export type EntityType = "user" | "host" | "ip" | "process" | "database" | "service" | "domain" | "alert";
export type Priority = "Critical" | "High" | "Moderate" | "Low";
export type BlastClass =
  | "CONFIRMED_COMPROMISE"
  | "SUSPECTED_LATERAL_MOVEMENT"
  | "OBSERVED_CONNECTION"
  | "POTENTIAL_EXPOSURE";

export interface Breakdown {
  component: string;
  label: string;
  value: number;
  weight: number;
  contribution: number;
  explanation: string;
}

export interface Scored {
  score: number;
  priority: Priority;
  breakdown: Breakdown[];
  disclaimer: string;
}

export interface EntitySummary {
  id: string;
  type: EntityType;
  name: string;
  category: string;
  criticality: number;
  in_inventory: boolean;
  degree: number;
  events: number;
  status: string | null;
}

export interface Summary {
  events: number;
  entities: number;
  relationships: number;
  occurrences: number;
  entity_types: Record<string, number>;
  relationship_types: Record<string, number>;
  events_by_source: Record<string, number>;
  source_systems: number;
  files: number;
  ingestion: Record<string, number>;
  time_range: { start: string | null; end: string | null };
  critical_assets: { id: string; name: string; type: string; category: string; criticality: number }[];
  incidents: number;
  incidents_by_priority: Record<string, number>;
  top_incident: null | {
    id: string;
    title: string;
    priority: Priority;
    score: number;
    start: string;
    end: string;
    identities: string[];
    affected_assets: string[];
    independent_sources: number;
    hypothesis_nodes: string[] | null;
  };
  histogram: { hour: string; events: number; suspicious: number }[];
  backend: Backend;
}

export interface Backend {
  mode: string;
  local_engine: string;
  neo4j: {
    configured: boolean;
    connected: boolean;
    synced: boolean;
    message: string;
    uri_host: string | null;
    database: string;
    last_sync?: string;
    synced_counts?: { nodes: number; relationships: number };
  };
}

export interface GraphNode {
  id: string;
  type: EntityType;
  name: string;
  category: string;
  criticality: number;
  in_inventory: boolean;
  status: string | null;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  count: number;
  basis: "observed" | "inferred";
  max_suspicion: number;
  first_seen: string;
  last_seen: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  limit: number;
}

export interface PathStep {
  from: string;
  to: string;
  relationship: string;
  relationship_id: string;
  timestamp: string;
  event_uid: string;
  source_system: string;
  source_file: string | null;
  source_row: number | null;
  basis: "observed" | "inferred";
  rule: string;
  suspicion: number;
  suspicion_rule: string | null;
  alert: string | null;
  description: string;
  total_occurrences: number;
}

export interface AttackPath extends Scored {
  channels?: PathChannels;
  nodes: string[];
  hops: number;
  steps: PathStep[];
  start: string;
  end: string;
  target: string;
  suspicious_hops: number;
  sources: string[];
  temporally_consistent: boolean;
  reasons: string[];
}

export interface PathResult {
  source: string;
  targets: string[];
  max_hops: number;
  since: string | null;
  window: { clock_skew_seconds: number; max_hop_gap_hours: number };
  paths: AttackPath[];
  total_valid_paths: number;
  rejected_temporally_impossible: { nodes: string[]; relationships: string[]; reason: string }[];
  structural_shortest_path: null | {
    nodes: string[];
    hops: number;
    relationships: string[];
    temporally_consistent: boolean;
    reason: string | null;
  };
  search: { engine: string; expansions: number; truncated: boolean; budget: number; candidate_cap: number };
}

export interface BlastNode {
  id: string;
  type: EntityType;
  name: string;
  category: string;
  criticality: number;
  hop: number;
  earliest_arrival: string | null;
  classification: BlastClass;
  impact: number;
  via: string[];
  suspicious_relationships: string[];
  analyst_status: string | null;
}

export interface BlastResult {
  source: string;
  max_hops: number;
  temporal: boolean;
  start_time: string | null;
  start_time_basis: string;
  nodes: BlastNode[];
  edges: string[];
  summary: {
    reachable: number;
    by_classification: Partial<Record<BlastClass, number>>;
    by_type: Record<string, number>;
    critical_assets: { id: string; name: string; criticality: number; hop: number; classification: BlastClass }[];
    accounts: string[];
  };
  growth: { hops: number; reachable: number }[];
  class_definitions: Record<BlastClass, string>;
}

export interface IncidentListItem {
  id: string;
  title: string;
  priority: Priority;
  score: number;
  start: string;
  end: string;
  identities: string[];
  affected_assets: string[];
  independent_sources: number;
  evidence_sources: string[];
  dismissed_by_source: boolean;
  alerts: number;
  seeds: number;
  supporting_events: number;
}

export interface Incident extends Scored {
  id: string;
  title: string;
  start: string;
  end: string;
  seed_events: string[];
  alerts: { uid: string; rule: string; technique: string | null; severity: number; disposition: string; timestamp: string }[];
  entities: Record<string, string[]>;
  affected_assets: string[];
  identities: string[];
  supporting_events: string[];
  evidence_sources: string[];
  independent_sources: number;
  correlation_links: { rule: string; a: string; b: string; detail: string }[];
  explanation: string[];
  timeline: { uid: string; timestamp: string; source_system: string; category: string; severity: number; seed: boolean; description: string }[];
  hypothesis: null | {
    source: string;
    target: string;
    nodes: string[];
    score: number;
    priority: Priority;
    steps: PathStep[];
    reasons: string[];
    channels?: PathChannels;
  };
  dismissed_by_source: boolean;
  analyst_confirmed: string[];
  channels?: IncidentChannels;
}

export interface EventRow {
  uid: string;
  event_id: string;
  timestamp: string;
  source_system: string;
  source_file: string;
  source_row: number;
  category: string;
  action: string;
  outcome: string;
  severity: number;
  description: string;
  notes: string[];
}

export interface FileSummary {
  file_name: string;
  sha256: string;
  size_bytes: number;
  source_system: string | null;
  source_label: string | null;
  records_read: number;
  accepted: number;
  rejected: number;
  duplicates: number;
  conflicts: number;
  warnings: number;
  first_event: string | null;
  last_event: string | null;
  loaded_at: string;
  issues: { source_file: string; source_row: number | null; level: string; message: string }[];
  error?: string;
}

export interface Settings {
  correlation_window_minutes: number;
  clock_skew_seconds: number;
  max_hop_gap_hours: number;
  default_max_hops: number;
  max_paths: number;
  search_budget: number;
  suspicion_threshold: number;
  recency_half_life_hours: number;
  weights: Record<string, number>;
}

export type ChannelId = "identity" | "endpoint" | "network" | "dns" | "data" | "detection";

export interface PathChannels {
  channels: ChannelId[];
  labels: Record<ChannelId, string>;
  steps: {
    step: number;
    relationship: string;
    from: string;
    to: string;
    timestamp: string;
    cells: Record<ChannelId, { state: "primary" | "corroborating" | "silent" | "blind" | "none"; records: string[]; count: number; expected: boolean }>;
    channels_with_evidence: number;
  }[];
  agreement: number;
  independent_channels: ChannelId[];
  multichannel_steps: number;
  single_channel_steps: number;
  silent_gaps: string[];
  summary: string;
}

export interface IncidentChannels {
  channels: ChannelId[];
  labels: Record<ChannelId, string>;
  rows: { entity: string; cells: Record<ChannelId, { count: number; state: "evidence" | "silent" | "blind" }>; channels_with_evidence: number }[];
  channels_with_evidence: ChannelId[];
  agreement: number;
  silent_observations: string[];
  single_channel_entities: string[];
  summary: string;
}

export interface SpreadMetrics {
  valid_paths: number;
  critical_paths: number;
  reachable: number;
  suspected: number;
  critical_assets_reachable: string[];
  crown_jewels_suspected: string[];
}

export interface ContainmentAction {
  kind: string;
  target: string;
  label: string;
  cost: number;
}

export interface ContainmentPlan {
  incident: string;
  source: string;
  effective_at: string | null;
  footholds: { id: string; since: string | null }[];
  before: SpreadMetrics;
  after: SpreadMetrics;
  plan: { action: ContainmentAction; risk_reduction_pct: number; after: SpreadMetrics }[];
  contained: boolean;
  pruned_as_redundant: string[];
  residual_paths: string[][];
  candidates: (ContainmentAction & { risk_reduction_pct: number; value_per_cost: number; crown_jewels_protected: string[]; after: SpreadMetrics })[];
  method: string;
  caveat: string;
}

export interface WhatIfResult {
  source: string;
  at: string | null;
  actions: ContainmentAction[];
  footholds: { id: string; since: string | null }[];
  before: SpreadMetrics;
  after: SpreadMetrics;
  prevented: string[];
  remaining_paths: string[][];
}

export interface Deviation {
  relationship_id: string;
  source: string;
  target: string;
  type: string;
  event_uid: string;
  timestamp: string;
  suspicion: number;
  baseline: string;
  d2: number;
  reference_tail: number;
  top_factor: string;
  contributions: Record<string, number>;
  explanation: string;
  volume: number;
  typical_volume: number;
}

export interface LiveUpdate {
  version: number;
  reason: string;
  at: string;
  events: number;
  entities: number;
  relationships: number;
  incidents: number;
  top_incident: { id: string; title: string; priority: Priority; score: number } | null;
  data_time: string | null;
  rebuild_ms: number;
  streamed: number;
}

export interface LiveStatus {
  version: number;
  streamed_events: number;
  pending: boolean;
  last_rebuild_ms: number;
  last_update: LiveUpdate | Record<string, never>;
  feed: { kind: string; at: string; uid: string; text: string }[];
  replay: {
    running: boolean; speed: number; finished: boolean; error: string | null; total: number; sent: number;
    preloaded: number; start: string | null; end: string | null; data_time: string | null; stopped: boolean;
  };
}
