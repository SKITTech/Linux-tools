import type { Lesson } from "./types";

export const LESSONS: Lesson[] = [
  // ===== BEGINNER =====
  {
    id: "gb1", level: "beginner", title: "init, clone & the working tree",
    summary: "Create a repo, clone one, and understand working tree / index / HEAD.",
    body: `Git tracks three areas: **working tree** (files on disk), **index/staging** (what \`git add\` queues), and **HEAD** (the last commit on the current branch).

- \`git init\` creates a fresh repo in the current folder.
- \`git clone <url>\` downloads a remote repo and sets \`origin\`.`,
    tryIt: ["git init my-repo && cd my-repo", "git clone https://github.com/octocat/Hello-World.git", "git status"],
    mistakes: ["Running git init inside an existing repo by mistake.", "Cloning into a non-empty directory."],
    checkpoints: [
      { q: "Which area does `git add` move files into?", choices: ["HEAD", "Working tree", "Index (staging)", "Stash"], answer: 2, explain: "`git add` stages changes into the index for the next commit." },
      { q: "What does `git clone` set up by default?", choices: ["A remote named upstream", "A remote named origin", "No remote", "Two remotes"], answer: 1, explain: "It adds the source as `origin`." },
      { q: "Where do uncommitted edits live?", choices: ["HEAD", "Index", "Working tree", "Reflog"], answer: 2, explain: "Edits sit in the working tree until staged." },
    ],
  },
  {
    id: "gb2", level: "beginner", title: "status, add, commit",
    summary: "The everyday triplet that records snapshots.",
    body: `\`git status\` shows what's changed. \`git add\` stages it. \`git commit\` records a snapshot with a message.`,
    tryIt: ["git status", "git add README.md", "git add .", "git commit -m \"docs: add README\""],
    mistakes: ["Committing with `-am` on new files (it only stages tracked files).", "Vague messages like 'fix'."],
    checkpoints: [
      { q: "Which flag opens an editor for a multi-line message?", choices: ["-m", "(no flag)", "-e", "-s"], answer: 1, explain: "Run `git commit` with no `-m` to open your editor." },
      { q: "`git commit -am` stages…", choices: ["All files", "Only tracked modified files", "Only new files", "Only deleted files"], answer: 1, explain: "`-a` stages modifications/deletions to TRACKED files only." },
      { q: "Best message format?", choices: ["fix", "stuff", "feat(auth): add OAuth callback", "wip"], answer: 2, explain: "Conventional, scoped, imperative messages help reviewers and tools." },
    ],
  },
  {
    id: "gb3", level: "beginner", title: "log & diff",
    summary: "Inspect history and see what changed.",
    body: `\`git log\` walks history. \`git diff\` shows changes between working tree, index, and commits.`,
    tryIt: ["git log --oneline --graph --decorate -20", "git diff", "git diff --staged", "git show HEAD"],
    mistakes: ["Forgetting `--staged` and wondering why diffs look empty after `git add`."],
    checkpoints: [
      { q: "Show changes already staged:", choices: ["git diff", "git diff --staged", "git log -p", "git status -s"], answer: 1, explain: "`--staged` (alias `--cached`) diffs index vs HEAD." },
      { q: "Compact one-line log:", choices: ["git log --short", "git log --oneline", "git log --tiny", "git log -1"], answer: 1, explain: "`--oneline` is the common compact view." },
      { q: "Show a commit's full patch:", choices: ["git diff <sha>", "git show <sha>", "git log <sha>", "git inspect <sha>"], answer: 1, explain: "`git show` displays metadata + patch." },
    ],
  },
  {
    id: "gb4", level: "beginner", title: "Branching basics",
    summary: "Create, switch, and delete branches.",
    body: `Branches are cheap pointers to commits. Use them per feature/fix.`,
    tryIt: ["git branch", "git switch -c feature/login", "git switch main", "git branch -d feature/login"],
    mistakes: ["Using `-D` (force delete) when `-d` would tell you commits are unmerged."],
    checkpoints: [
      { q: "Modern command to create+switch:", choices: ["git checkout -b X", "git switch -c X", "Both work", "git branch X --switch"], answer: 2, explain: "Both work; `switch -c` is the modern preferred form." },
      { q: "Safe delete a merged branch:", choices: ["git branch -d X", "git branch -D X", "git rm X", "git delete X"], answer: 0, explain: "`-d` refuses if unmerged; `-D` forces." },
      { q: "List remote branches too:", choices: ["git branch", "git branch -a", "git branch -r only", "git ls-remote"], answer: 1, explain: "`-a` shows all local + remote-tracking branches." },
    ],
  },
  {
    id: "gb5", level: "beginner", title: "Merge basics",
    summary: "Bring one branch's changes into another.",
    body: `\`git merge\` combines histories. A fast-forward moves the pointer; otherwise a merge commit is created.`,
    tryIt: ["git switch main", "git merge feature/login", "git merge --no-ff feature/login"],
    mistakes: ["Merging without first pulling latest `main`."],
    recovery: ["`git merge --abort` to back out before commit.", "`git reset --merge ORIG_HEAD` to undo a just-finished merge."],
    checkpoints: [
      { q: "Force a merge commit even when FF is possible:", choices: ["--squash", "--no-ff", "--ff-only", "--rebase"], answer: 1, explain: "`--no-ff` always records a merge commit." },
      { q: "Abort an in-progress merge:", choices: ["git reset --hard", "git merge --abort", "git stash", "git revert"], answer: 1, explain: "Safer than reset; only works before merge is finalized." },
      { q: "Squash all changes into one commit on target:", choices: ["--no-ff", "--squash", "--ff-only", "-m squash"], answer: 1, explain: "`--squash` stages combined diff for a single new commit." },
    ],
  },
  {
    id: "gb6", level: "beginner", title: "Remotes: fetch, pull, push",
    summary: "Sync with origin and other remotes.",
    body: `\`fetch\` downloads refs without changing your branch. \`pull\` = fetch + merge (or rebase). \`push\` uploads commits.`,
    tryIt: ["git remote -v", "git fetch origin", "git pull --rebase origin main", "git push -u origin feature/login"],
    mistakes: ["Default `pull` creates merge commits; consider `pull.rebase=true`."],
    checkpoints: [
      { q: "Update tracking info without merging:", choices: ["git pull", "git fetch", "git rebase", "git sync"], answer: 1, explain: "`fetch` is the safe inspector." },
      { q: "Set upstream on first push:", choices: ["git push", "git push -u origin <branch>", "git remote add", "git track"], answer: 1, explain: "`-u` sets upstream so future `git push/pull` work bare." },
      { q: "Make pulls rebase by default:", choices: ["pull.rebase=true", "merge.ff=only", "fetch.prune=true", "push.default=current"], answer: 0, explain: "Cleaner linear history." },
    ],
  },
  {
    id: "gb7", level: "beginner", title: "Resolving a simple conflict",
    summary: "Edit the conflict markers, add, commit.",
    body: `When merge/rebase can't auto-merge, Git inserts \`<<<<<<<\`, \`=======\`, \`>>>>>>>\` markers. Edit, then \`git add\` and \`git commit\` (or \`git rebase --continue\`).`,
    tryIt: ["git status", "code path/to/file", "git add path/to/file", "git commit", "git merge --abort"],
    mistakes: ["Leaving conflict markers in committed files."],
    recovery: ["`git merge --abort` or `git rebase --abort` to bail out cleanly."],
    checkpoints: [
      { q: "After fixing a merge conflict you must…", choices: ["git push", "git add + git commit (or --continue)", "git reset", "git stash"], answer: 1, explain: "Stage the resolved files, then commit or `--continue`." },
      { q: "Abort an in-progress rebase:", choices: ["git rebase --skip", "git rebase --abort", "git reset --hard", "git revert"], answer: 1, explain: "`--abort` restores the pre-rebase state." },
      { q: "Use a 3-way merge tool:", choices: ["git mergetool", "git diff -3", "git resolve", "git fix"], answer: 0, explain: "`git mergetool` launches the configured tool." },
    ],
  },

  // ===== INTERMEDIATE =====
  {
    id: "gi1", level: "intermediate", title: "Rebase vs Merge",
    summary: "Linear history with rebase, traceable merges with merge.",
    body: `**Merge** preserves true history. **Rebase** replays your commits on top of another base for a linear history. Never rebase commits you've pushed publicly without coordination.`,
    tryIt: ["git fetch origin", "git rebase origin/main", "git rebase --continue", "git rebase --abort"],
    mistakes: ["Rebasing shared branches — rewrites history others may have."],
    recovery: ["`git reflog` then `git reset --hard <old-sha>` to recover pre-rebase state."],
    checkpoints: [
      { q: "Rebase your feature on latest main:", choices: ["git rebase main", "git merge main", "git pull main", "git switch main"], answer: 0, explain: "Replays your commits on top of main." },
      { q: "Safer alternative to public force push:", choices: ["push --force", "push --force-with-lease", "push -u", "push --mirror"], answer: 1, explain: "Fails if remote moved — protects teammates." },
      { q: "Recover pre-rebase commits:", choices: ["git stash pop", "git reflog + reset", "git cherry-pick", "git fsck only"], answer: 1, explain: "Reflog has every HEAD movement for ~90 days." },
    ],
  },
  {
    id: "gi2", level: "intermediate", title: "Interactive rebase (squash/fixup)",
    summary: "Clean history before sharing.",
    body: `\`git rebase -i <base>\` opens a todo list: \`pick\`, \`reword\`, \`edit\`, \`squash\`, \`fixup\`, \`drop\`. Use \`fixup\` to silently fold a small commit into the previous one.`,
    tryIt: ["git rebase -i HEAD~5", "git commit --fixup <sha>", "git rebase -i --autosquash HEAD~10"],
    mistakes: ["Squashing into the wrong base; always confirm the base SHA."],
    checkpoints: [
      { q: "Fold commit into previous keeping prev message:", choices: ["squash", "fixup", "reword", "edit"], answer: 1, explain: "`fixup` discards the new message; `squash` opens an editor." },
      { q: "Auto-arrange fixups during interactive rebase:", choices: ["--rebase-merges", "--autosquash", "--root", "--onto"], answer: 1, explain: "Combine with `git commit --fixup <sha>`." },
      { q: "Rebase against fork point of upstream:", choices: ["git rebase HEAD", "git rebase --fork-point upstream/main", "git rebase --onto self", "git rebase origin"], answer: 1, explain: "`--fork-point` uses reflog to compute base." },
    ],
  },
  {
    id: "gi3", level: "intermediate", title: "Stash workflows",
    summary: "Set work aside without committing.",
    body: `\`git stash push -u -m "wip"\` saves tracked + untracked changes. Pop or apply to restore.`,
    tryIt: ["git stash push -u -m \"wip: login form\"", "git stash list", "git stash show -p stash@{0}", "git stash pop"],
    mistakes: ["Forgetting `-u` so new (untracked) files are lost."],
    recovery: ["`git fsck --lost-found` can recover dropped stashes for a while."],
    checkpoints: [
      { q: "Include untracked files in a stash:", choices: ["-i", "-u", "-a", "--keep-index"], answer: 1, explain: "`-u` for untracked; `-a` adds ignored too." },
      { q: "Apply and remove a stash:", choices: ["git stash apply", "git stash pop", "git stash drop", "git stash show"], answer: 1, explain: "`pop` applies + drops; `apply` keeps the stash." },
      { q: "Stash only staged changes:", choices: ["--staged", "--cached", "--keep-index plus add", "Not possible"], answer: 0, explain: "Modern git supports `git stash push --staged`." },
    ],
  },
  {
    id: "gi4", level: "intermediate", title: "Tags & releases",
    summary: "Mark versions for releases.",
    body: `Lightweight tags = a name pointing at a commit. Annotated tags carry message + signer — use these for releases.`,
    tryIt: ["git tag v1.0.0", "git tag -a v1.0.0 -m \"v1 GA\"", "git push origin v1.0.0", "git push origin --tags"],
    mistakes: ["Moving a published tag — breaks anyone who already fetched it."],
    checkpoints: [
      { q: "Best tag type for releases:", choices: ["Lightweight", "Annotated", "Branch", "Stash"], answer: 1, explain: "Annotated tags store metadata and can be signed." },
      { q: "Push a single tag to origin:", choices: ["git push", "git push origin v1.0.0", "git push --tags", "git tag --push"], answer: 1, explain: "Specify the tag ref." },
      { q: "List tags matching a pattern:", choices: ["git tag -l 'v1.*'", "git tags v1*", "git list tag", "git show tag"], answer: 0, explain: "`-l` accepts a glob." },
    ],
  },
  {
    id: "gi5", level: "intermediate", title: "cherry-pick & revert",
    summary: "Move or undo individual commits safely.",
    body: `\`cherry-pick\` applies a commit elsewhere. \`revert\` creates a NEW commit that undoes another — safe for shared branches.`,
    tryIt: ["git cherry-pick <sha>", "git cherry-pick -x <sha>  # records origin", "git revert <sha>", "git revert -m 1 <merge-sha>"],
    mistakes: ["Reverting a merge without `-m` (which parent to keep)."],
    checkpoints: [
      { q: "Undo a public commit safely:", choices: ["git reset --hard", "git revert", "git rebase -i", "git push --force"], answer: 1, explain: "`revert` adds a new commit instead of rewriting history." },
      { q: "Cherry-pick + record source SHA:", choices: ["-r", "-x", "-s", "-n"], answer: 1, explain: "`-x` appends '(cherry picked from commit ...)'." },
      { q: "Revert a merge commit needs:", choices: ["-m <parent>", "-x", "-n", "-s"], answer: 0, explain: "Pick which parent line to keep." },
    ],
  },
  {
    id: "gi6", level: "intermediate", title: "Bisect basics",
    summary: "Binary search for the bad commit.",
    body: `\`git bisect\` walks history with you to find the commit that introduced a bug.`,
    tryIt: ["git bisect start", "git bisect bad", "git bisect good v1.0.0", "git bisect reset"],
    mistakes: ["Forgetting `git bisect reset` to leave bisect mode."],
    checkpoints: [
      { q: "Mark current commit as broken:", choices: ["git bisect good", "git bisect bad", "git bisect skip", "git bisect end"], answer: 1, explain: "Tell git which side it's on." },
      { q: "End bisect and return:", choices: ["git bisect stop", "git bisect reset", "git bisect quit", "git checkout HEAD"], answer: 1, explain: "`reset` restores prior branch." },
      { q: "Automate via script:", choices: ["git bisect auto", "git bisect run ./test.sh", "git bisect script", "git bisect ci"], answer: 1, explain: "Exit code drives good/bad." },
    ],
  },

  // ===== ADVANCED =====
  {
    id: "ga1", level: "advanced", title: "reflog recovery",
    summary: "The undo buffer for HEAD movements.",
    body: `Every HEAD change (commit, reset, rebase, checkout) is logged in \`reflog\`. Look up the prior SHA and \`git reset --hard\` to it.`,
    tryIt: ["git reflog", "git reset --hard HEAD@{2}", "git fsck --lost-found"],
    mistakes: ["Trusting reflog past 90 days — gc may have pruned."],
    recovery: ["Use `reflog` BEFORE running aggressive `gc` or `prune`."],
    checkpoints: [
      { q: "How long do reflog entries last by default?", choices: ["7 days", "30 days", "90 days", "Forever"], answer: 2, explain: "`gc.reflogExpire=90.days` by default." },
      { q: "Reset to your HEAD as of 3 moves ago:", choices: ["HEAD~3", "HEAD@{3}", "HEAD^3", "HEAD$3"], answer: 1, explain: "`HEAD@{N}` walks the reflog; `HEAD~N` walks parents." },
      { q: "Find dangling commits the reflog missed:", choices: ["git log --all", "git fsck --lost-found", "git stash list", "git gc"], answer: 1, explain: "fsck lists dangling objects." },
    ],
  },
  {
    id: "ga2", level: "advanced", title: "Hooks: pre-commit, commit-msg",
    summary: "Run local checks before commits land.",
    body: `Hooks live in \`.git/hooks/*\` (not versioned). Use a manager (Husky, lefthook, pre-commit) to share them across the team.`,
    tryIt: ["ls .git/hooks", "echo '#!/bin/sh\\nnpm test' > .git/hooks/pre-commit", "chmod +x .git/hooks/pre-commit"],
    mistakes: ["Slow hooks blocking commits — keep them fast or run async in CI."],
    checkpoints: [
      { q: "Hook that validates commit message format:", choices: ["pre-commit", "commit-msg", "pre-push", "post-merge"], answer: 1, explain: "`commit-msg` gets the message path as arg 1." },
      { q: "Skip hooks for a single commit (use sparingly):", choices: ["--no-verify", "--skip-hooks", "--bypass", "--quiet"], answer: 0, explain: "`-n/--no-verify` skips pre-commit & commit-msg." },
      { q: "Share hooks across a team:", choices: [".git/hooks committed", "Husky/lefthook/pre-commit framework", "Email them", "Wiki"], answer: 1, explain: ".git is not versioned; use a manager." },
    ],
  },
  {
    id: "ga3", level: "advanced", title: "Submodules pitfalls",
    summary: "Repos inside repos — handle with care.",
    body: `\`git submodule add <url> path\` pins a specific commit of another repo. Clones must use \`--recurse-submodules\` and updates need explicit \`submodule update --remote\`.`,
    tryIt: ["git clone --recurse-submodules <url>", "git submodule update --init --recursive", "git submodule update --remote --merge"],
    mistakes: ["Forgetting `--recurse-submodules` on clone, ending with empty folders.", "Pushing parent without pushing submodule first."],
    checkpoints: [
      { q: "Make a fresh clone include submodules:", choices: ["--shallow", "--recurse-submodules", "--with-subs", "--init"], answer: 1, explain: "Plus `--init` in some workflows." },
      { q: "Update submodules to latest remote ref:", choices: ["git submodule sync", "git submodule update --remote", "git pull --recurse", "git fetch --all"], answer: 1, explain: "Pulls tracked branch tip into each submodule." },
      { q: "Why ordering matters when pushing:", choices: ["GitHub limit", "Parent points to submodule SHA; that SHA must exist on remote first", "Hooks", "Tags"], answer: 1, explain: "Otherwise clones can't fetch the pinned SHA." },
    ],
  },
  {
    id: "ga4", level: "advanced", title: "Worktrees & sparse checkout",
    summary: "Multiple working copies, partial trees.",
    body: `\`git worktree\` lets one repo back several working directories. \`sparse-checkout\` keeps only some paths in your tree — useful in monorepos.`,
    tryIt: ["git worktree add ../hotfix hotfix/api", "git worktree list", "git sparse-checkout init --cone", "git sparse-checkout set apps/web packages/ui"],
    mistakes: ["Manually deleting worktree folders — always use `git worktree remove`."],
    checkpoints: [
      { q: "Add a second working directory:", choices: ["git clone --shallow", "git worktree add", "git checkout --detach", "git submodule add"], answer: 1, explain: "`worktree add <path> <branch>`." },
      { q: "Cone mode in sparse-checkout means:", choices: ["Random patterns", "Directory-prefix patterns (fast)", "Hide branches", "Compress objects"], answer: 1, explain: "Faster, dir-prefix-only matching." },
      { q: "Clean up a worktree:", choices: ["rm -rf", "git worktree remove", "git branch -D", "git stash"], answer: 1, explain: "Keeps repo metadata consistent." },
    ],
  },
  {
    id: "ga5", level: "advanced", title: "Signing commits (GPG/SSH)",
    summary: "Prove who committed.",
    body: `Configure a signing key, then \`git commit -S\` (or set \`commit.gpgsign=true\`). GitHub supports both GPG and SSH signing.`,
    tryIt: ["git config --global user.signingkey <KEYID>", "git config --global commit.gpgsign true", "git config --global gpg.format ssh", "git log --show-signature"],
    mistakes: ["No signing-key trust on the host → 'gpg failed to sign the data'."],
    checkpoints: [
      { q: "Verify signatures in log:", choices: ["--signed", "--show-signature", "-S", "--gpg"], answer: 1, explain: "Annotates each commit with sig status." },
      { q: "Use SSH key instead of GPG:", choices: ["gpg.format=ssh", "ssh.key=true", "commit.signer=ssh", "sign.mode=ssh"], answer: 0, explain: "Plus a `allowed_signers` file for verification." },
      { q: "Sign one commit ad hoc:", choices: ["git commit -s", "git commit -S", "git commit --gpg", "git sign-commit"], answer: 1, explain: "`-s` only adds Signed-off-by trailer." },
    ],
  },
];
