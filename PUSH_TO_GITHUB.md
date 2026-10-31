# Publishing this repository to GitHub

This folder is a complete git repository: 20+ commits and the tags `v1.0.0`, `v1.1.0` and `v1.2.0`.
Pick **one** of the three options below.

Repository name: `attackgraph-lens-hackfront-t2`
Description: *AttackGraph Lens — Explainable graph-based threat hunting, temporal attack-path discovery, alert
correlation and blast-radius analysis for hackFront India T2.1 GraphOps.*
Suggested topics: `cybersecurity` `graph` `threat-hunting` `incident-response` `attack-path` `blast-radius`
`fastapi` `react` `networkx` `neo4j` `hackathon`

---

## Step 0 (recommended): put your names on it

Commits currently use the placeholder author "AttackGraph Lens Team". Replace it with your own GitHub identity
before publishing (use your GitHub *noreply* e-mail if you do not want your address public:
GitHub → Settings → Emails → "Keep my email addresses private").

```bash
git config user.name  "Your Name"
git config user.email "12345678+yourhandle@users.noreply.github.com"

# rewrite the existing commits with your identity (keeps messages, dates and the AI co-author trailer)
git rebase -r --root --exec "git commit --amend --no-edit --reset-author"
# re-point the release tags to the rewritten commits
git tag -f -a v1.2.0 -m "AttackGraph Lens 1.2.0 — real-time live mode" HEAD
git tag -d v1.0.0 v1.1.0        # earlier tags referred to the old commits; recreate them if you want them
```

Also edit `LICENSE` (copyright line) and add a **Team** section to `README.md`, then commit:
`git commit -am "docs: team and licence holder"`.

---

## Option A — GitHub CLI (fastest)

```bash
gh auth login                                   # once
cd attackgraph-lens-hackfront-t2
gh repo create attackgraph-lens-hackfront-t2 --public --source=. --push \
  --description "AttackGraph Lens — Explainable graph-based threat hunting, temporal attack-path discovery, alert correlation and blast-radius analysis for hackFront India T2.1 GraphOps."
git push origin --tags
gh repo edit --add-topic cybersecurity,graph,threat-hunting,incident-response,attack-path,blast-radius,fastapi,react,networkx,neo4j,hackathon
```

## Option B — plain git (any machine)

1. On github.com → **New repository** → name `attackgraph-lens-hackfront-t2`, **Public**, do **not** add a README,
   licence or .gitignore (the repo already has them).
2. Then:

```bash
cd attackgraph-lens-hackfront-t2
git remote add origin https://github.com/<your-username>/attackgraph-lens-hackfront-t2.git
git branch -M main
git push -u origin main
git push origin --tags
```

(GitHub asks for a username and a **personal access token** as the password: Settings → Developer settings →
Personal access tokens → fine-grained, repository *Contents: Read and write*.)

## Option C — from the git bundle file

```bash
git clone attackgraph-lens-hackfront-t2.bundle attackgraph-lens-hackfront-t2
cd attackgraph-lens-hackfront-t2
# then Option A or B
```

Avoid the browser "Upload files" button: it drops the commit history and tags, limits each upload to 100 files,
and evaluators value a real history.

---

## After pushing

1. **Check**: open the repo page; the README should render with screenshots; the **Actions** tab should start the CI
   workflow (backend tests, frontend build, browser tests). If CI fails, the job log says why.
2. **Release**: Releases → *Draft a new release* → tag `v1.2.0` → title "AttackGraph Lens 1.2.0" → paste
   `docs/RELEASE_NOTES.md` → attach `AttackGraph_Lens_HackFront_T2_Submission.zip` (built UI included, runs without
   Node.js) and `attackgraph_lens_demo.mp4` → *Publish*.
3. **Secrets check** (already done locally, repeat if you added files): no `.env`, keys or passwords in the repo.
   `git log -p | grep -iE "password=|api[_-]?key|BEGIN .*PRIVATE KEY"` should show only the documented placeholders
   (`NEO4J_PASSWORD=<password>`, the guide itself, and the fake value in `test_neo4j_adapter.py`).
4. Put the repository URL into the hackFront submission form and the activity document.
