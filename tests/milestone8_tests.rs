use clap::CommandFactory;
use clap_complete::Shell;
use plens::cli::Cli;
use plens::render::tui::TuiApp;
use plens::store::HistoryItem;

#[test]
fn test_shell_completions_generation() {
    let mut cmd = Cli::command();
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell] {
        let mut buffer = Vec::new();
        clap_complete::generate(shell, &mut cmd, "plens", &mut buffer);
        assert!(!buffer.is_empty(), "Completions for {:?} was empty", shell);
    }
}

#[test]
fn test_tui_app_state_and_navigation() {
    let history = vec![
        HistoryItem {
            id: "scan-alpha".into(),
            targets: "10.0.0.1".into(),
            start_time: "2026-10-31T10:00:00Z".into(),
            preset: "standard".into(),
            risk_score: 10,
            risk_grade: "A".into(),
            findings_count: 0,
        },
        HistoryItem {
            id: "scan-beta".into(),
            targets: "192.168.1.10".into(),
            start_time: "2026-10-31T11:00:00Z".into(),
            preset: "quick".into(),
            risk_score: 80,
            risk_grade: "D".into(),
            findings_count: 2,
        },
    ];

    let mut app = TuiApp::new(history);
    assert_eq!(app.selected_index, 0);

    // Navigation down
    app.select_next();
    assert_eq!(app.selected_index, 1);

    // Filter by target
    app.filter_query = "192.168".into();
    let filtered = app.filtered_history();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].id, "scan-beta");

    // Clear filter
    app.filter_query.clear();
    assert_eq!(app.filtered_history().len(), 2);
}

#[test]
fn test_man_page_file_exists() {
    let man_path = std::path::Path::new("docs/man/plens.1");
    assert!(man_path.exists());
    let content = std::fs::read_to_string(man_path).unwrap();
    assert!(content.contains(".TH PLENS 1"));
    assert!(content.contains("PortLens"));
}
