# GitRecon Architecture Deep Trace

## Current Data Flow (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: DETECT (detect.rs)                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Target URL → probe_one_path()                                             │
│      │                                                                      │
│      ├─► HEAD → parse_head() → branch, head_sha1                          │
│      ├─► config → GitConfigParser → remote_url                             │
│      ├─► index → verify DIRC magic                                        │
│      ├─► packed-refs → verify format                                       │
│      ├─► logs/HEAD → verify log format                                     │
│      └─► objects/info/packs → verify "P " pattern                           │
│                                                                              │
│   Returns: DetectResult { git_url, branch, head_sha1, ... }                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: MAP (mapper.rs)                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Input: git_url, branch (from DetectResult)                               │
│                                                                              │
│   1. Fetch all META_FILES concurrently:                                     │
│      - HEAD, config, index, packed-refs, logs/*, objects/info/packs, etc.   │
│                                                                              │
│   2. Parse HEAD → get ref or commit SHA1                                   │
│      If ref: fetch ref file → get commit SHA1                               │
│                                                                              │
│   3. Parse config → get branches, remote URLs                              │
│      For each branch: fetch refs/heads/{branch}, logs/refs/heads/{branch}   │
│                                                                              │
│   4. Parse packed-refs → extract ref SHA1s                                  │
│                                                                              │
│   5. Parse index → extract ALL current blob SHA1s + filenames               │
│      IndexParser::parse() → Vec<IndexEntry>                                │
│      Each entry: { sha1, filename, mode, file_size }                      │
│                                                                              │
│   6. Extract SHA1s from logs (contains commit history)                     │
│                                                                              │
│   7. Extract SHA1s from refs (branch heads)                                │
│                                                                              │
│   8. Fetch pack files from objects/info/packs:                             │
│      For each pack: fetch .idx file                                        │
│      PackIndexParser::parse() → extract ALL object SHA1s in pack           │
│                                                                              │
│   9. Classify SHA1s:                                                        │
│      - blob_sha1s = from index                                              │
│      - commit_sha1s = all_sha1s - blob_sha1s                               │
│      (Note: tree_sha1s is collected but never used!)                       │
│                                                                              │
│   Returns: MapResult {                                                       │
│       commit_sha1s: HashSet<String>,    ─┐                                  │
│       tree_sha1s:   HashSet<String>,     │ NOT USED for traversal!          │
│       blob_sha1s:   HashSet<String>,    ─┼─► These are only used for       │
│       pack_sha1s:   Vec<String>,        │    streaming, not tree walking   │
│       index_entries: Vec<IndexEntry>,   │                                    │
│       branches: Vec<String>,            │                                    │
│       remote_urls: Vec<...>             │                                    │
│   }                                                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 3: STREAM (streamer.rs)                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Input: git_url, MapResult, save_dir (optional)                            │
│                                                                              │
│   1. Build sha1_to_file mapping:                                            │
│      sha1_to_file = HashMap from index_entries only ❌                      │
│      (This is the KEY LIMITATION - no tree-derived filenames!)              │
│                                                                              │
│   2. Build SHA1 list to process:                                            │
│      all_sha1s = blob_sha1s ∪ commit_sha1s (deduplicated)                   │
│      (Note: tree_sha1s NOT included!)                                       │
│                                                                              │
│   3. For each SHA1 in all_sha1s (parallel):                                  │
│      fetch_and_process(sha1):                                                │
│         │                                                                    │
│         ├─► Download object from git_url/objects/xx/xxxxxxxx...              │
│         │                                                                    │
│         ├─► Parse object (ObjectParser):                                     │
│         │   │                                                                │
│         │   ├─► BLOB:                                                       │
│         │   │   ├─ Save to disk (if --save) using sha1_to_file              │
│         │   │   ├─ Scan for secrets (scan_content)                          │
│         │   │   └─ Extract tech stack                                       │
│         │   │                                                                │
│         │   ├─► COMMIT:                                                     │
│         │   │   ├─ Parse commit metadata (author, email)                    │
│         │   │   ├─ Scan commit message for secrets ❌ (no tree traversal)   │
│         │   │   └─ Return metadata only                                     │
│         │   │                                                                │
│         │   └─► TREE:                                                       │
│         │       ├─ Parse tree entries (parse_tree)                          │
│         │       ├─ Extract tech stack from filenames ❌                      │
│         │       └─ RETURN ONLY tech info ❌❌ NO RECURSIVE TRAVERSAL        │
│         │                                                                    │
│   Returns: StreamResult { findings, contributors, tech_stack, ... }         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 4: RECONSTRUCT (reconstructor.rs) - OPTIONAL (--save flag)            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Input: sha1_to_file (from index only!)                                    │
│                                                                              │
│   For each (sha1, filename) in sha1_to_file:                                 │
│      ├─► Download blob from git_url/objects/xx/xxxxxxxx...                   │
│      ├─► Parse and verify it's a blob                                       │
│      └─► Write to disk at output_dir/filename                               │
│                                                                              │
│   ISSUE: If no index file, sha1_to_file is EMPTY!                            │
│   RESULT: No files reconstructed, even if blobs were scanned ❌              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## The 5 Critical Gaps (Visualized)

```
GAP #1: No Recursive Tree Traversal
═══════════════════════════════════════════════════════════════════════════════

Current (streamer.rs:1128-1135):
┌─────────────────────────────────────────────────────────────────────────────┐
│ When tree object encountered:                                              │
│   parse_tree(obj) → entries Vec<TreeEntry>                                 │
│   For each entry:                                                          │
│      if entry.is_blob(): collect (sha1, name) for tech stack              │
│      if entry.is_tree(): IGNORED ❌                                        │
│                                                                              │
│ Result: Only top-level files discovered!                                    │
│   src/main.rs  ✓                                                           │
│   src/utils/   ✗ (nested tree - never processed)                           │
└─────────────────────────────────────────────────────────────────────────────┘

Required:
┌─────────────────────────────────────────────────────────────────────────────┐
│ When tree object encountered:                                              │
│   parse_tree(obj) → entries Vec<TreeEntry>                                 │
│   For each entry:                                                          │
│      if entry.is_blob():                                                   │
│         ✓ Collect for scanning                                             │
│         ✓ Collect for reconstruction (with full path)                      │
│      if entry.is_tree():                                                   │
│         ✓ ADD TO QUEUE for recursive processing                            │
│                                                                              │
│   Process queue until all nested trees traversed                           │
│                                                                              │
│ Result: All files at all depths discovered!                                 │
└─────────────────────────────────────────────────────────────────────────────┘


GAP #2: No Commit Graph Walking
═══════════════════════════════════════════════════════════════════════════════

Current (mapper.rs):
┌─────────────────────────────────────────────────────────────────────────────┐
│ Mapper collects SHA1s from:                                                │
│   ✓ Index file (current working directory state)                           │
│   ✓ Pack files (all objects in packs)                                      │
│   ✓ Logs/refs (commit SHA1s only)                                         │
│                                                                              │
│ Missing:                                                                   │
│   ✗ Walking HEAD → commit → tree → blobs                                  │
│   ✗ Walking commit → parents → their trees → blobs                        │
│                                                                              │
│ Result: Historical blobs not discovered if not in index/packs              │
└─────────────────────────────────────────────────────────────────────────────┘

Required:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Add commit graph walker:                                                   │
│   1. Start from HEAD commit SHA1                                           │
│   2. Parse commit → get tree SHA1 + parent SHA1s                           │
│   3. Recursively traverse tree → collect all blob SHA1s                    │
│   4. For each parent: goto step 2 (BFS/DFS)                                │
│   5. Union all discovered blob SHA1s + paths                               │
│                                                                              │
│ Result: Complete repository blob enumeration from commit history            │
└─────────────────────────────────────────────────────────────────────────────┘


GAP #3: Index File Dependency
═══════════════════════════════════════════════════════════════════════════════

Current (streamer.rs:763-766):
┌─────────────────────────────────────────────────────────────────────────────┐
│ sha1_to_file built ONLY from index_entries:                                 │
│   for entry in &map_result.index_entries:                                   │
│       sha1_to_file.insert(entry.sha1, entry.filename)                       │
│                                                                              │
│ Problem:                                                                    │
│   - Bare repos often have no index file                                    │
│   - Historical files not in index                                          │
│   - sha1_to_file remains empty or incomplete                                │
│                                                                              │
│ Impact on reconstruction:                                                   │
│   - Reconstructor needs sha1_to_file for filenames                          │
│   - Without mapping: files saved as "[blob:abc123]" ❌                      │
└─────────────────────────────────────────────────────────────────────────────┘

Required:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Build sha1_to_file from MULTIPLE sources:                                   │
│   1. Index file (current state) - fallback                                 │
│   2. Tree traversal (HEAD commit tree) - primary                            │
│   3. Commit history trees (all commits) - complete coverage                │
│                                                                              │
│ Process:                                                                    │
│   If index exists: use it (fast path)                                       │
│   Else: walk commit graph → traverse trees → build full mapping             │
│                                                                              │
│ Result: Complete SHA1→path mapping even without index file                 │
└─────────────────────────────────────────────────────────────────────────────┘


GAP #4: Deleted Files Not Scanned
═══════════════════════════════════════════════════════════════════════════════

Current (streamer.rs:1017-1019):
┌─────────────────────────────────────────────────────────────────────────────┐
│ let is_deleted = !current_blobs.contains(sha1);                              │
│                                                                              │
│ For deleted files:                                                         │
│   ✓ Findings created with is_deleted=true                                   │
│   ✗ But may be skipped in some paths                                       │
│   ✗ No prioritization for historical secrets                                │
│                                                                              │
│ Issue: Deleted files = HIGH VALUE targets                                   │
│   - Old credentials before rotation                                         │
│   - Historical API keys                                                     │
│   - Leaked secrets that were "fixed" by deletion                            │
└─────────────────────────────────────────────────────────────────────────────┘

Required:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Prioritize deleted files:                                                   │
│   1. Mark is_deleted properly for ALL paths                                 │
│   2. Sort blobs by priority:                                                │
│      priority = (is_deleted ? 0 : 1) + (is_sensitive ? 0 : 2)               │
│   3. Scan deleted files FIRST (high value targets)                         │
│   4. Report deleted findings prominently                                   │
│                                                                              │
│ Result: Historical secrets properly discovered and prioritized              │
└─────────────────────────────────────────────────────────────────────────────┘


GAP #5: Pack-only Limitation
═══════════════════════════════════════════════════════════════════════════════

Current (mapper.rs:362-388):
┌─────────────────────────────────────────────────────────────────────────────┐
│ Pack discovery:                                                              │
│   1. Fetch objects/info/packs                                               │
│   2. Parse pack names from "P pack-<sha1>.pack" lines                       │
│   3. For each pack: fetch objects/pack/pack-<sha1>.idx                      │
│   4. Parse .idx file for all object SHA1s                                   │
│                                                                              │
│ Issues:                                                                     │
│   - If info/packs doesn't list all packs → missed ❌                        │
│   - If info/packs is missing → no packs discovered ❌                       │
│   - No fallback to directly scan objects/pack/ directory                    │
└─────────────────────────────────────────────────────────────────────────────┘

Required:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Enhanced pack discovery:                                                     │
│   1. Try objects/info/packs (primary)                                      │
│   2. Fallback: directly try objects/pack/pack-*.idx patterns               │
│   3. Handle both loose and packed object storage                            │
│                                                                              │
│ Process:                                                                    │
│   if info/packs exists: use listed packs                                    │
│   else:                                                                     │
│      try common pack name patterns                                          │
│      fallback to loose objects only                                         │
│                                                                              │
│ Result: Maximum pack file coverage                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Integration Points for Patches

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PATCH INTEGRATION ARCHITECTURE                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [mapper.rs]                                                                │
│      │                                                                      │
│      ├─► ADD: commit_graph_walker()                                         │
│      │   - Input: HEAD commit SHA1                                         │
│      │   - Output: (all_blob_sha1s, sha1_to_file_mapping)                  │
│      │   - Process: BFS/DFS commit → tree traversal                        │
│      │                                                                     │
│      └─► MODIFY: run() to call commit_graph_walker()                       │
│          - Integrate with existing SHA1 collection                         │
│          - Union commit_graph_sha1s with existing sha1s                    │
│          - Use tree-derived sha1_to_file if index missing                   │
│                                                                              │
│  [git_parser.rs]                                                            │
│      │                                                                      │
│      └─► ADD: TreeWalker struct                                            │
│          - recursive_tree_traverse()                                        │
│          - Input: tree SHA1, path_prefix                                   │
│          - Output: HashMap<sha1, full_path>                                 │
│          - Process: Queue-based tree traversal                             │
│                                                                              │
│  [streamer.rs]                                                              │
│      │                                                                      │
│      ├─► MODIFY: sha1_to_file building                                     │
│      │   - Use tree-derived mapping if index missing                        │
│      │   - Union index-derived + tree-derived mappings                      │
│      │                                                                     │
│      └─► MODIFY: blob processing priority                                  │
│          - Prioritize deleted/sensitive files                              │
│          - Sort by: (deleted, sensitive, path)                             │
│                                                                              │
│  [reconstructor.rs]                                                         │
│      │                                                                      │
│      └─► ENHANCE: Use improved sha1_to_file mapping                        │
│          - Support tree-derived filenames                                  │
│          - Fallback for unnamed blobs                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Expected Flow After Patches

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FIXED FLOW                                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Detect → get HEAD SHA1                                                 │
│                                                                              │
│  2. Map:                                                                     │
│     ├─ Existing: fetch metadata, parse index, pack, logs                   │
│     ├─ NEW: commit_graph_walker(HEAD_SHA1)                                 │
│     │   ├─ Walk commits (BFS)                                              │
│     │   ├─ For each commit: traverse tree recursively                     │
│     │   └─ Collect ALL blob SHA1s + paths                                 │
│     │                                                                     │
│     └─ Merge: Union all SHA1s + paths                                      │
│                                                                              │
│  3. Stream:                                                                  │
│     ├─ Build complete sha1_to_file (index + tree-derived)                   │
│     ├─ Prioritize: deleted > sensitive > regular                           │
│     └─ Scan all blobs with proper filenames                                 │
│                                                                              │
│  4. Reconstruct:                                                             │
│     └─ Save all files with correct paths (even without index)              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Test Cases for Validation

```
Test 1: Nested Directory Structure
═══════════════════════════════════════════════════════════════════════════════
repo/
├── src/
│   ├── main.rs
│   └── utils/
│       └── helper.rs    ← Must be discovered!
└── tests/
    └── test.rs          ← Must be discovered!

Expected: All files scanned and reconstructed


Test 2: Bare Repository (No Index)
═══════════════════════════════════════════════════════════════════════════════
.git/
├── HEAD
├── objects/
│   ├── xx/
│   │   └── xxxxxx...   (loose objects)
│   └── pack/
│       └── pack-xxx.idx
├── refs/
│   └── heads/
│       └── main
└── (no index file)

Expected: All files discovered via commit graph + tree traversal


Test 3: Historical Secrets
═══════════════════════════════════════════════════════════════════════════════
Commit history:
├── HEAD: (current) - no secrets
├── HEAD~1: deleted .env with API_KEY=xxx
└── HEAD~2: old config with password=yyy

Expected: Historical secrets from HEAD~1, HEAD~2 discovered


Test 4: Large Repository
═══════════════════════════════════════════════════════════════════════════════
- 10,000+ files
- Deep directory nesting
- Mixed loose and packed objects

Expected: All files discovered, reasonable performance
```
