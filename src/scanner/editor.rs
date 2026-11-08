use super::json::Value;
use super::{Report, fs::Directory};
use std::{ffi::OsStr, path::Path};

pub(super) fn scan(root: &Directory, report: &mut Report) {
    if let Some(editor) = report.child(root, ".vscode") {
        for (name, kind) in [("settings.json", 0), ("tasks.json", 1), ("launch.json", 2)] {
            if let Some(value) = report.document(&editor, OsStr::new(name), true) {
                let path = editor.path.join(name);
                match kind {
                    0 => settings(&value, &path, report),
                    1 => tasks(&value, &path, report),
                    _ => launches(&value, &path, report),
                }
            }
        }
    }
    for name in report.entries(root) {
        if Path::new(&name).extension() != Some(OsStr::new("code-workspace")) {
            continue;
        }
        if let Some(workspace) = report.document(root, &name, true) {
            let path = Path::new(&name);
            if let Some(value) = workspace.get("settings") {
                settings(value, path, report);
            }
            if let Some(value) = workspace.get("tasks") {
                tasks(value, path, report);
            }
            if let Some(value) = workspace.get("launch") {
                launches(value, path, report);
            }
            if let Some(folders) = workspace.get("folders") {
                if !folders.as_array().is_some_and(|items| {
                    items.iter().all(|v| {
                        v.get("path").and_then(Value::as_str) == Some(".") && v.get("uri").is_none()
                    })
                }) {
                    report.issue(path, "Workspace folder references were not followed; scan each referenced folder separately.");
                }
            }
        }
    }
}
fn settings(value: &Value, path: &Path, report: &mut Report) {
    let Some(settings) = value.as_object() else {
        report.issue(path, "Editor settings must be an object.");
        return;
    };
    if !settings.is_empty() {
        report.finding(path, "settings", "EDITOR_SETTINGS", "review", "Workspace settings can affect editor and extension behavior; review unfamiliar settings. Only selected execution-related keys have specific rules.");
    }
    settings_keys(value, path, report);
}
fn settings_keys(value: &Value, path: &Path, report: &mut Report) {
    let Some(settings) = value.as_object() else {
        return;
    };
    for (key, value) in settings {
        if key.starts_with('[') && key.ends_with(']') {
            settings_keys(value, path, report);
            continue;
        }
        if key.starts_with("terminal.integrated.profiles.")
            || key.starts_with("terminal.integrated.automationProfile.")
            || key.starts_with("terminal.integrated.defaultProfile.")
            || key.starts_with("terminal.integrated.shell")
            || key.starts_with("terminal.integrated.env.")
        {
            report.finding(path, "settings/terminal.integrated.*", "EDITOR_TERMINAL", "high", "Workspace terminal configuration can select an executable, supply arguments or alter its environment; review before opening a terminal.");
        }
        if (key == "security.workspace.trust.enabled" && value != &Value::Bool(true))
            || (key == "terminal.integrated.allowInUntrustedWorkspace"
                && value != &Value::Bool(false))
            || (key == "task.allowAutomaticTasks" && value.as_str() != Some("off"))
        {
            report.finding(path, "settings/trust-or-automatic-tasks", "EDITOR_PROTECTION", "high", "A setting requests weaker trust or automatic-execution controls. Effective behavior depends on the editor version and permitted setting scope.");
        }
        if key == "git.path"
            || key == "git.useIntegratedAskPass"
            || key.ends_with(".executablePath")
            || key.ends_with(".interpreterPath")
            || key.ends_with(".defaultInterpreterPath")
            || key.ends_with(".runtime")
            || key.ends_with(".server.path")
            || key.ends_with(".tsdk")
            || key == "clangd.path"
        {
            report.finding(path, "settings/tool-path", "EDITOR_TOOL", "high", "Workspace settings select or alter an editor tool; review the executable and the extension's trust behavior.");
        }
    }
}
fn tasks(value: &Value, path: &Path, report: &mut Report) {
    if !value.is_object() {
        report.issue(path, "Task configuration must be an object.");
        return;
    }
    if let Some(items) = value.get("tasks") {
        let Some(items) = items.as_array() else {
            report.issue(path, "Tasks must be an array.");
            return;
        };
        for (index, task) in items.iter().enumerate() {
            if !task.is_object() {
                report.issue(path, "Task entry must be an object.");
                continue;
            }
            let automatic =
                task.pointer("/runOptions/runOn") == Some(&Value::String("folderOpen".into()));
            report.finding(path, format!("tasks/{index}"), if automatic { "EDITOR_AUTORUN" } else { "EDITOR_TASK" }, if automatic { "high" } else { "review" }, if automatic { "A task requests execution when the folder opens; Restricted Mode or automatic-task controls may block it." } else { "A workspace task can execute project-supplied commands when invoked." });
        }
    }
    inputs(value, path, report);
}
fn launches(value: &Value, path: &Path, report: &mut Report) {
    if !value.is_object() {
        report.issue(path, "Launch configuration must be an object.");
        return;
    }
    if let Some(items) = value.get("configurations") {
        let Some(items) = items.as_array() else {
            report.issue(path, "Launch configurations must be an array.");
            return;
        };
        for (index, configuration) in items.iter().enumerate() {
            if !configuration.is_object() {
                report.issue(path, "Launch entry must be an object.");
                continue;
            }
            report.finding(path, format!("configurations/{index}"), "EDITOR_LAUNCH", "review", "Debugger configuration can launch programs, tasks or debugger commands when used; review before starting it.");
        }
    }
    inputs(value, path, report);
}
fn inputs(value: &Value, path: &Path, report: &mut Report) {
    if let Some(inputs) = value.get("inputs") {
        let Some(inputs) = inputs.as_array() else {
            report.issue(path, "Editor inputs must be an array.");
            return;
        };
        if inputs
            .iter()
            .any(|v| v.get("type").and_then(Value::as_str) == Some("command"))
        {
            report.finding(
                path,
                "inputs",
                "EDITOR_COMMAND_INPUT",
                "high",
                "An editor input invokes an extension command when evaluated.",
            );
        }
    }
}
