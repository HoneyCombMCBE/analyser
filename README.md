# minecraftEdu Sigs

Automated Ghidra headless analysis for Minecraft Education Edition binaries.

## Usage

1. **Extract** `Minecraft.Windows.exe` from the MEE AppX package
2. **Create a release** on this repo, upload the exe as an asset
3. **Run workflow** → Actions → Analyze Binary → `workflow_dispatch`
   - `release_tag`: the tag from step 2
   - `asset_name`: `Minecraft.Windows.exe`
4. **Workflow outputs** are uploaded back to the release:
   - `functions.json` — all function names, addresses, sizes, hex bytes
   - `ghidra_project.zip` — full analyzed Ghidra project
5. **Match locally** with BDS PDB using a separate matching tool (not in CI)
