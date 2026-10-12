//! Forge (forgecode) agent: instructions-file integration.
//!
//! Forge reads `AGENTS.md` from three locations (global `~/.forge/AGENTS.md`,
//! the git root, and the working directory — see forge's
//! `ForgeCustomInstructionsService`). Forge has no external process-hook API,
//! so RTK integrates at the *rules file* tier: the shared awareness block is
//! upserted into an `AGENTS.md`, and the agent prefixes `rtk` itself. Command
//! rewriting still goes through the shared registry via `rtk rewrite`, which a
//! future in-process forge hook (`EventHandle` on `ToolcallStart`) can call
//! without any change here.

use super::*;
use crate::core::user_dirs;

/// The `AGENTS.md` forge reads for global custom instructions.
fn forge_global_agents_md() -> Result<PathBuf> {
    let home = user_dirs::home().context("Cannot determine home directory")?;
    Ok(home.join(".forge").join(AGENTS_MD))
}

pub fn run_forge_mode(global: bool, ctx: InitContext) -> Result<()> {
    if global {
        run_forge_mode_at(&forge_global_agents_md()?, ctx)
    } else {
        run_forge_mode_at(&user_dirs::current_dir()?, ctx)
    }
}

fn run_forge_mode_at(path: &Path, ctx: InitContext) -> Result<()> {
    let path = path.join(AGENTS_MD);

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        if ctx.dry_run {
            println!("[dry-run] would create directory {}", parent.display());
        } else {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
    }

    let action = write_rtk_block(
        &path,
        RTK_INSTRUCTIONS,
        "rtk instructions",
        "rtk init --forge",
        ctx,
    )?;

    if !ctx.dry_run {
        match action {
            RtkBlockUpsert::Added | RtkBlockUpsert::Updated => {
                println!("\nRTK configured for Forge.\n");
                println!("  Instructions: {}", path.display());
                println!("  Forge has no command hook; the agent prefixes rtk itself.");
                println!("  Restart Forge. Test with: git status\n");
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn uninstall_forge(global: bool, ctx: InitContext) -> Result<()> {
    if global {
        uninstall_forge_at(&forge_global_agents_md()?, ctx)
    } else {
        uninstall_forge_at(&user_dirs::current_dir()?, ctx)
    }
}

fn uninstall_forge_at(path: &Path, ctx: InitContext) -> Result<()> {
    let path = path.join(AGENTS_MD);

    if !path.exists() {
        println!("No RTK instructions found in {}", path.display());
        return Ok(());
    }

    let content =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let (new_content, removed) = remove_rtk_block(&content);

    if !removed {
        println!("No RTK instructions found in {}", path.display());
        return Ok(());
    }

    if ctx.dry_run {
        println!(
            "[dry-run] would remove RTK instructions from {}",
            path.display()
        );
    } else {
        atomic_write(&path, &new_content)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        println!("[ok] Removed RTK instructions from {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_forge_mode_local_writes_agents_md() {
        let dir = tempfile::TempDir::new().unwrap();
        run_forge_mode_at(dir.path(), InitContext::default()).unwrap();
        let content = fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert!(content.contains(RTK_BLOCK_START));
        assert!(content.contains("Golden Rule"));
    }

    #[test]
    fn test_uninstall_forge_local_removes_block() {
        let dir = tempfile::TempDir::new().unwrap();
        run_forge_mode_at(dir.path(), InitContext::default()).unwrap();
        uninstall_forge_at(dir.path(), InitContext::default()).unwrap();
        let content = fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert!(!content.contains(RTK_BLOCK_START));
    }
}
