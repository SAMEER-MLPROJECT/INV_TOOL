# Recording checklist (voice-over version)

The included video has captions but no voice. If the organiser expects a narrated recording:

1. Check the official duration and format limits on the participant dashboard first.
2. `./scripts/run_local.sh`; open http://127.0.0.1:8000 in Chrome at 1600×900 or 1920×1080, browser zoom 100 %.
3. **Settings & Data → Reset to sample dataset** so the state is clean and incident IDs match the script.
4. Close other tabs and notifications; hide bookmarks bar; use a dark desktop.
5. Record the screen (OBS Studio, or Windows `Win+G`, or macOS `Cmd+Shift+5`) with a headset microphone.
6. Follow `DEMO_SCRIPT.md` row by row; pause ~1 s after each click so viewers can follow.
7. Show real execution only — do not cut to slides for any functional claim.
8. Say once, early: "All data is synthetic; this is a prototype."
9. If mentioning Neo4j, say it is implemented but was not demonstrated against a live database (unless you have since
   connected AuraDB and can show **Settings → Connect & sync to Neo4j** succeeding).
10. Export to MP4 (H.264), check audio levels, and confirm length ≤ the official limit.

To regenerate the automated captioned recording: start the server, then
`python demo/record_demo.py --chrome <path-to-chrome>`.
